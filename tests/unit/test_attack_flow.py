"""Attack Flow parser: ordering, branching, malformed input, provenance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import stix_builders as sb
from hqc.common.errors import (
    DatasetNotFoundError,
    MalformedSourceDataError,
    MissingRequiredFieldError,
)
from hqc.common.schemas import DataOrigin, StepProvenance
from hqc.mitre.attack_flow import (
    AttackFlowDocument,
    load_attack_flow_file,
    parse_attack_flow,
    source_group_for,
)
from hqc.mitre.attack_flow_corpus import build_corpus, technique_coverage
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.stix_parser import parse_attack_bundle

SHA = "f" * 64


def parse(bundle: dict[str, Any], **kwargs: Any) -> AttackFlowDocument:
    return parse_attack_flow(
        bundle,
        document_id=kwargs.pop("document_id", "Doc"),
        source_file="Doc.json",
        source_sha256=SHA,
        source_version="test-corpus@1",
        **kwargs,
    )


def paths(doc: AttackFlowDocument) -> list[list[str]]:
    return [s.technique_ids for s in doc.sequences]


# 1. normal ordered flow ----------------------------------------------------------------


def test_linear_flow() -> None:
    bundle = sb.flow_bundle(
        [
            sb.action("a", "T1566.001", ["b"]),
            sb.action("b", "T1059.001", ["c"]),
            sb.action("c", "T1003"),
        ],
        starts=["a"],
    )
    doc = parse(bundle)
    assert paths(doc) == [["T1566.001", "T1059.001", "T1003"]]
    assert doc.stats.paths == 1 and doc.stats.attack_actions == 3


# 2. multiple steps (with tactics, longer chain) -------------------------------------------


def test_multiple_steps_keep_tactics() -> None:
    chain = ["T1190", "T1059.004", "T1110.001", "T1021.004", "T1041"]
    tactics = ["TA0001", "TA0002", "TA0006", "TA0008", "TA0010"]
    nodes = [
        sb.action(f"s{i}", t, [f"s{i + 1}"] if i < len(chain) - 1 else None, tactic_id=tac)
        for i, (t, tac) in enumerate(zip(chain, tactics, strict=True))
    ]
    doc = parse(sb.flow_bundle(nodes, starts=["s0"]))
    seq = doc.sequences[0]
    assert seq.technique_ids == chain
    assert [s.tactic_id for s in seq.steps] == tactics
    assert [s.position for s in seq.steps] == [0, 1, 2, 3, 4]


# 3. branching -----------------------------------------------------------------------------


def test_branches_follow_source_reference_order() -> None:
    # effect_refs lists c before b: c's branch must come first (source order, not ID order).
    bundle = sb.flow_bundle(
        [sb.action("a", "T1566", ["c", "b"]), sb.action("b", "T1003"), sb.action("c", "T1059")],
        starts=["a"],
    )
    assert paths(parse(bundle)) == [["T1566", "T1059"], ["T1566", "T1003"]]


def test_or_operator_and_condition_branches() -> None:
    bundle = sb.flow_bundle(
        [
            sb.action("a", "T1190", ["op:or"]),
            sb.operator("or", "OR", ["b", "cond:x"]),
            sb.action("b", "T1505.003"),
            sb.condition("x", on_true=["c"], on_false=["d"]),
            sb.action("c", "T1078"),
            sb.action("d", "T1110"),
        ],
        starts=["a"],
    )
    assert paths(parse(bundle)) == [
        ["T1190", "T1505.003"],
        ["T1190", "T1078"],  # on_true before on_false
        ["T1190", "T1110"],
    ]


def test_and_operator_never_orders_parallel_predecessors() -> None:
    """Co-occurring prerequisites (AND) must not be chained into an invented order."""
    bundle = sb.flow_bundle(
        [
            sb.action("p1", "T1078", ["op:and"]),
            sb.action("p2", "T1021.001", ["op:and"]),
            sb.operator("and", "AND", ["c"]),
            sb.action("c", "T1486"),
        ],
        starts=["p1", "p2"],
    )
    result = paths(parse(bundle))
    assert result == [["T1078", "T1486"], ["T1021.001", "T1486"]]
    assert not any({"T1078", "T1021.001"} <= set(p) for p in result)


def test_condition_as_start_node() -> None:
    bundle = sb.flow_bundle(
        [sb.condition("x", on_true=["a"]), sb.action("a", "T1059")], starts=["cond:x"]
    )
    assert paths(parse(bundle)) == [["T1059"]]


def test_max_paths_truncation_is_flagged() -> None:
    bundle = sb.flow_bundle(
        [sb.action("a", "T1566", ["b", "c", "d"]), *(sb.action(x, "T1059") for x in "bcd")],
        starts=["a"],
    )
    doc = parse(bundle, max_paths=2)
    assert doc.stats.paths == 2 and doc.stats.truncated_at_max_paths


# 4. invalid / malformed flows -------------------------------------------------------------


@pytest.mark.parametrize(
    "bundle",
    [
        {"type": "report"},
        {"type": "bundle"},
        {"type": "bundle", "objects": [{"type": "attack-action"}]},
        {"type": "bundle", "objects": []},  # no attack-flow
    ],
)
def test_malformed_bundles(bundle: dict[str, Any]) -> None:
    with pytest.raises(MalformedSourceDataError):
        parse(bundle)


def test_two_flows_rejected() -> None:
    bundle = sb.flow_bundle([sb.action("a", "T1059")], starts=["a"])
    second = dict(bundle["objects"][0], id="attack-flow--second")
    bundle["objects"].append(second)
    with pytest.raises(MalformedSourceDataError, match="expected one"):
        parse(bundle)


def test_missing_start_refs() -> None:
    bundle = sb.flow_bundle([sb.action("a", "T1059")], starts=["a"])
    bundle["objects"][0]["start_refs"] = []
    with pytest.raises(MissingRequiredFieldError):
        parse(bundle)


def test_dangling_references_rejected() -> None:
    with pytest.raises(MalformedSourceDataError, match="missing object"):
        parse(sb.flow_bundle([sb.action("a", "T1059", ["ghost"])], starts=["a"]))
    with pytest.raises(MalformedSourceDataError, match="not a flow node"):
        parse(sb.flow_bundle([sb.action("a", "T1059")], starts=["ghost"]))


def test_non_list_references_rejected() -> None:
    node = sb.action("a", "T1059")
    node["effect_refs"] = "attack-action--b"
    with pytest.raises(MalformedSourceDataError, match="non-list"):
        parse(sb.flow_bundle([node], starts=["a"]))


def test_invalid_json_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    with pytest.raises(MalformedSourceDataError):
        load_attack_flow_file(bad, "v")


# 5. missing technique reference -----------------------------------------------------------


def test_actions_without_attack_technique_are_skipped_with_gap() -> None:
    bundle = sb.flow_bundle(
        [
            sb.action("a", "T1566", ["x"]),
            sb.action("x", None, ["y"]),  # no technique at all
            sb.action("y", "AML.T0051", ["b"]),  # MITRE ATLAS, not ATT&CK
            sb.action("b", "T1059"),
        ],
        starts=["a"],
    )
    doc = parse(bundle)
    seq = doc.sequences[0]
    assert seq.technique_ids == ["T1566", "T1059"]
    assert [s.gap_before for s in seq.steps] == [0, 2]
    assert len(seq.action_ids) == 4  # skipped actions remain in provenance
    assert doc.stats.missing_technique_actions == 1
    assert doc.stats.non_attack_actions == 1
    kinds = {a.action_id.split("--")[1]: a.technique_kind for a in doc.actions}
    assert kinds == {"a": "attack", "x": "missing", "y": "non_attack", "b": "attack"}


def test_paths_without_any_attack_technique_are_dropped_and_counted() -> None:
    bundle = sb.flow_bundle(
        [sb.action("a", None, ["b", "c"]), sb.action("b", "AML.T0010"), sb.action("c", "T1059")],
        starts=["a"],
    )
    doc = parse(bundle)
    assert paths(doc) == [["T1059"]]
    assert doc.stats.paths == 2 and doc.stats.paths_without_attack_techniques == 1


def test_technique_id_whitespace_is_trimmed() -> None:
    doc = parse(sb.flow_bundle([sb.action("a", " T1059.001 ")], starts=["a"]))
    assert paths(doc) == [["T1059.001"]]
    assert doc.actions[0].technique_id_raw == " T1059.001 "  # raw value preserved


# 6. duplicate technique occurrences ---------------------------------------------------------


def test_duplicate_techniques_are_preserved() -> None:
    bundle = sb.flow_bundle(
        [
            sb.action("a", "T1059", ["b"]),
            sb.action("b", "T1003", ["c"]),
            sb.action("c", "T1059", ["d"]),
            sb.action("d", "T1059"),
        ],
        starts=["a"],
    )
    assert paths(parse(bundle)) == [["T1059", "T1003", "T1059", "T1059"]]


def test_cycles_terminate_and_are_flagged() -> None:
    bundle = sb.flow_bundle(
        [
            sb.action("a", "T1059", ["b"]),
            sb.action("b", "T1003", ["a", "c"]),
            sb.action("c", "T1041"),
        ],
        starts=["a"],
    )
    doc = parse(bundle)
    assert paths(doc) == [["T1059", "T1003", "T1041"]]
    assert doc.sequences[0].cycle_truncated is True
    assert doc.stats.cycle_truncated_paths == 1


def test_unreachable_actions_counted_not_sequenced() -> None:
    bundle = sb.flow_bundle([sb.action("a", "T1059"), sb.action("orphan", "T1486")], starts=["a"])
    doc = parse(bundle)
    assert paths(doc) == [["T1059"]]
    assert doc.stats.unreachable_actions == 1


# 7. preservation of source ordering (regression) ---------------------------------------------


def test_regression_source_order_is_not_alphabetical_order() -> None:
    source_order = ["T1566.001", "T1204.002", "T1059.001", "T1003.001", "T1021.002", "T1041"]
    assert source_order != sorted(source_order)  # the fixture is deliberately unsorted
    nodes = [
        sb.action(f"n{i}", t, [f"n{i + 1}"] if i + 1 < len(source_order) else None)
        for i, t in enumerate(source_order)
    ]
    # Shuffle object order inside the bundle: ordering must come from the graph only.
    nodes = list(reversed(nodes))
    doc = parse(sb.flow_bundle(nodes, starts=["n0"]))
    parsed = doc.sequences[0].technique_ids
    assert parsed == source_order
    assert parsed != sorted(parsed)
    chain = doc.sequences[0].to_attack_chain("19.2")
    assert chain.technique_ids == source_order


# 8. provenance retention ---------------------------------------------------------------------


def test_sequence_provenance_and_attack_chain_conversion() -> None:
    bundle = sb.flow_bundle(
        [sb.action("a", "T1566", ["b"], tactic_id="TA0001"), sb.action("b", "T1059")],
        starts=["a"],
        name="Example Incident (Alt)",
    )
    doc = parse(bundle, document_id="Example Incident (Alt)")
    seq = doc.sequences[0]
    assert seq.sequence_id == "Example Incident (Alt)::p00000"
    assert seq.document_id == "Example Incident (Alt)"
    assert seq.source_group == "Example Incident"
    assert seq.source_file == "Doc.json" and seq.source_sha256 == SHA
    assert seq.source_version == "test-corpus@1"
    assert seq.flow_id == "attack-flow--test" and seq.flow_name == "Example Incident (Alt)"
    assert seq.action_ids == ["attack-action--a", "attack-action--b"]
    assert seq.parser_version == "1"

    chain = seq.to_attack_chain("19.2")
    assert chain.data_origin is DataOrigin.REAL
    assert chain.attack_version == "19.2"
    assert all(s.provenance is StepProvenance.DOCUMENTED for s in chain.steps)
    assert all(s.event_id is None and s.timestamp is None for s in chain.steps)
    assert chain.steps[0].source == "attack-flow:Example Incident (Alt)"
    assert "action_id=attack-action--a" in chain.steps[0].evidence
    assert chain.steps[0].tactic_id == "TA0001"


def test_execution_start_is_kept_as_source_metadata() -> None:
    doc = parse(
        sb.flow_bundle([sb.action("a", "T1059", execution_start="2021-01-01T00:00:00Z")], ["a"])
    )
    assert doc.actions[0].execution_start == "2021-01-01T00:00:00Z"


@pytest.mark.parametrize(
    ("name", "group"),
    [
        ("CISA AA22-138B VMWare Workspace (TA1)", "CISA AA22-138B VMWare Workspace"),
        ("Equifax Breach (with Mitigations/Detections)", "Equifax Breach"),
        ("SolarWinds", "SolarWinds"),
        ("(only parens)", "(only parens)"),
    ],
)
def test_source_group_for(name: str, group: str) -> None:
    assert source_group_for(name) == group


def test_excluded_scope() -> None:
    doc = parse(sb.flow_bundle([sb.action("a", "T1059")], ["a"], scope="attack-tree"))
    assert doc.excluded and doc.exclusion_reason is not None
    assert not parse(sb.flow_bundle([sb.action("a", "T1059")], ["a"])).excluded


# --- corpus building ----------------------------------------------------------------------


def _write_flows(tmp_path: Path) -> Path:
    d = tmp_path / "stix"
    d.mkdir()
    flows = {
        "B Incident": sb.flow_bundle(
            [sb.action("a", "T1086", ["b"]), sb.action("b", "T1003")], ["a"], name="B Incident"
        ),
        "A Incident": sb.flow_bundle([sb.action("a", "T0866")], ["a"], name="A Incident"),
        "Tree": sb.flow_bundle([sb.action("a", "T1059")], ["a"], name="Tree", scope="attack-tree"),
    }
    for name, bundle in flows.items():
        (d / f"{name}.json").write_text(json.dumps(bundle))
    return d


def test_build_corpus_summary_and_coverage(tmp_path: Path) -> None:
    kb = AttackKnowledgeBase.from_data(parse_attack_bundle(sb.attack_bundle(), sb.TEST_VERSION))
    corpus = build_corpus(_write_flows(tmp_path), "test@1", kb=kb)
    s = corpus.summary
    assert [d.document_id for d in corpus.documents] == ["A Incident", "B Incident", "Tree"]
    assert (s.documents_total, s.documents_included, s.source_groups) == (3, 2, 2)
    assert s.sequences == 2
    assert s.coverage is not None
    assert s.coverage.active == ["T1003"]
    assert s.coverage.revoked == {"T1086": "T1059.001"}
    assert s.coverage.unknown == ["T0866"]
    assert len(corpus.included_documents) == 2
    # Processed corpus keeps source IDs unchanged (no silent remapping of revoked IDs).
    b = next(d for d in corpus.documents if d.document_id == "B Incident")
    assert b.sequences[0].technique_ids == ["T1086", "T1003"]


def test_build_corpus_without_kb_and_missing_dir(tmp_path: Path) -> None:
    assert build_corpus(_write_flows(tmp_path), "test@1").summary.coverage is None
    with pytest.raises(DatasetNotFoundError):
        build_corpus(tmp_path / "empty", "test@1")


def test_technique_coverage_deprecated() -> None:
    kb = AttackKnowledgeBase.from_data(parse_attack_bundle(sb.attack_bundle(), sb.TEST_VERSION))
    cov = technique_coverage({"T1999", "T1059"}, kb)
    assert cov.deprecated == ["T1999"] and cov.active == ["T1059"]
