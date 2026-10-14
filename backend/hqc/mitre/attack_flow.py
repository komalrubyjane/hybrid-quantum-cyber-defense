"""MITRE Attack Flow (STIX 2.1 extension) parser.

Ordering comes ONLY from the flow graph explicitly encoded in the source:

    attack-flow.start_refs -> node
    attack-action.effect_refs / attack-operator.effect_refs -> next nodes
    attack-condition.on_true_refs (then on_false_refs) -> next nodes

Each maximal path from a start node is one ordered sequence. Branches are explored in
the order the references appear in the source document. Nothing is ever sorted by
technique ID or name, and no order is derived from co-occurrence (e.g. AND-operator
predecessors produce separate paths; no order is invented between them).

Policies (recorded in the per-sequence provenance):
- Actions without a technique, or with a non-ATT&CK technique (e.g. MITRE ATLAS
  ``AML.*``), are kept in ``action_ids`` but produce no technique step; the number of
  such actions skipped immediately before a step is stored as ``gap_before``.
- A path stops when it would revisit a node (cycle); it is flagged ``cycle_truncated``.
- Actions unreachable from ``start_refs`` are counted and not sequenced.
- Duplicate technique occurrences are preserved.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import ConfigDict, Field

from hqc.common.errors import MalformedSourceDataError, MissingRequiredFieldError
from hqc.common.provenance import sha256_bytes
from hqc.common.schemas.attack import AttackChain, AttackStep
from hqc.common.schemas.base import (
    TACTIC_ID_REGEX,
    TECHNIQUE_ID_REGEX,
    DataOrigin,
    HQCModel,
    NonEmptyStr,
    StepProvenance,
    TacticId,
    TechniqueId,
)

PARSER_VERSION = "1"
DEFAULT_MAX_PATHS_PER_DOCUMENT = 10_000
DEFAULT_EXCLUDED_SCOPES: frozenset[str] = frozenset({"attack-tree"})
"""``attack-tree`` flows are illustrative (e.g. the corpus "Example Attack Tree" tutorial)."""

_TECHNIQUE_RE = re.compile(TECHNIQUE_ID_REGEX)
_TACTIC_RE = re.compile(TACTIC_ID_REGEX)
_VARIANT_SUFFIX_RE = re.compile(r"\s*\([^)]*\)\s*$")
FLOW_NODE_TYPES = frozenset({"attack-action", "attack-operator", "attack-condition"})

TechniqueKind = Literal["attack", "non_attack", "missing"]


class FlowAction(HQCModel):
    """One ``attack-action`` as found in the source (OBSERVED SOURCE DATA).

    String fields are stored exactly as in the source (no whitespace stripping).
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=False)

    action_id: NonEmptyStr
    name: str
    technique_id_raw: str | None
    technique_id: TechniqueId | None = Field(description="Set only for valid ATT&CK IDs.")
    technique_kind: TechniqueKind
    tactic_id: TacticId | None = None
    execution_start: str | None = None


class FlowSequenceStep(HQCModel):
    position: int = Field(ge=0, description="Index among technique steps of this sequence.")
    action_id: NonEmptyStr
    technique_id: TechniqueId
    tactic_id: TacticId | None = None
    gap_before: int = Field(ge=0, description="Non-technique actions skipped before this step.")


class FlowSequence(HQCModel):
    """One ordered path through a flow, with full provenance (DERIVED from the graph)."""

    sequence_id: NonEmptyStr
    document_id: NonEmptyStr
    source_group: NonEmptyStr = Field(
        description="Grouping key for leakage-safe splits (variants of one document share it)."
    )
    source_file: NonEmptyStr
    source_sha256: NonEmptyStr
    source_version: NonEmptyStr
    flow_id: NonEmptyStr
    flow_name: NonEmptyStr
    scope: str | None = None
    path_index: int = Field(ge=0)
    action_ids: list[NonEmptyStr] = Field(description="All actions on the path, in order.")
    steps: list[FlowSequenceStep] = Field(min_length=1)
    cycle_truncated: bool = False
    parser_version: NonEmptyStr = PARSER_VERSION

    @property
    def technique_ids(self) -> list[str]:
        """ATT&CK technique IDs in source order (duplicates preserved)."""
        return [s.technique_id for s in self.steps]

    def to_attack_chain(self, attack_version: str) -> AttackChain:
        """Convert to the shared AttackChain contract (DOCUMENTED steps, no timestamps)."""
        return AttackChain(
            chain_id=self.sequence_id,
            steps=[
                AttackStep(
                    technique_id=s.technique_id,
                    tactic_id=s.tactic_id,
                    confidence=1.0,
                    source=f"attack-flow:{self.document_id}",
                    provenance=StepProvenance.DOCUMENTED,
                    evidence=[
                        f"flow_id={self.flow_id}",
                        f"action_id={s.action_id}",
                        f"position={s.position}",
                        f"gap_before={s.gap_before}",
                        f"source_sha256={self.source_sha256}",
                    ],
                )
                for s in self.steps
            ],
            data_origin=DataOrigin.REAL,
            attack_version=attack_version,
        )


class FlowDocumentStats(HQCModel):
    actions: int = 0
    attack_actions: int = 0
    non_attack_actions: int = 0
    missing_technique_actions: int = 0
    unreachable_actions: int = 0
    paths: int = 0
    paths_without_attack_techniques: int = 0
    cycle_truncated_paths: int = 0
    truncated_at_max_paths: bool = False


class AttackFlowDocument(HQCModel):
    """Parsed document: metadata, actions and ordered sequences."""

    document_id: NonEmptyStr
    source_group: NonEmptyStr
    source_file: NonEmptyStr
    source_sha256: NonEmptyStr
    source_version: NonEmptyStr
    flow_id: NonEmptyStr
    flow_name: NonEmptyStr
    scope: str | None = None
    excluded: bool = False
    exclusion_reason: str | None = None
    actions: list[FlowAction]
    sequences: list[FlowSequence]
    stats: FlowDocumentStats


def source_group_for(flow_name: str) -> str:
    """Leakage-grouping key derived from the flow *name* (not the file name).

    A trailing parenthetical variant label is stripped, so 'X (TA1)', 'X (Alt)' and
    'X (with Mitigations/Detections)' all map to 'X'. The flow name is used because
    variant documents can have unrelated file names (e.g. 'OpenClaw.json').
    """
    return _VARIANT_SUFFIX_RE.sub("", flow_name).strip() or flow_name


def _classify_technique(raw: Any) -> tuple[str | None, TechniqueKind]:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None, "missing"
    candidate = str(raw).strip()
    if _TECHNIQUE_RE.match(candidate):
        return candidate, "attack"
    return None, "non_attack"


def _successors(node: dict[str, Any]) -> list[str]:
    kind = node["type"]
    if kind in ("attack-action", "attack-operator"):
        refs = node.get("effect_refs") or []
    elif kind == "attack-condition":
        refs = (node.get("on_true_refs") or []) + (node.get("on_false_refs") or [])
    else:
        refs = []
    if not isinstance(refs, list):
        raise MalformedSourceDataError(f"{node['id']} has non-list references")
    return refs


def _parse_action(obj: dict[str, Any]) -> FlowAction:
    technique_id, kind = _classify_technique(obj.get("technique_id"))
    tactic_raw = obj.get("tactic_id")
    tactic = tactic_raw.strip() if isinstance(tactic_raw, str) else None
    return FlowAction(
        action_id=obj["id"],
        name=str(obj.get("name", "")),
        technique_id_raw=obj.get("technique_id"),
        technique_id=technique_id,
        technique_kind=kind,
        tactic_id=tactic if tactic and _TACTIC_RE.match(tactic) else None,
        execution_start=obj.get("execution_start"),
    )


def parse_attack_flow(
    bundle: dict[str, Any],
    document_id: str,
    source_file: str,
    source_sha256: str,
    source_version: str,
    max_paths: int = DEFAULT_MAX_PATHS_PER_DOCUMENT,
    excluded_scopes: frozenset[str] = DEFAULT_EXCLUDED_SCOPES,
) -> AttackFlowDocument:
    """Parse one Attack Flow STIX bundle into ordered sequences."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise MalformedSourceDataError(f"{source_file}: not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise MalformedSourceDataError(f"{source_file}: bundle has no 'objects' list")
    by_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or "id" not in obj or "type" not in obj:
            raise MalformedSourceDataError(f"{source_file}: object without 'id'/'type'")
        by_id[obj["id"]] = obj

    flows = [o for o in objects if o["type"] == "attack-flow"]
    if len(flows) != 1:
        raise MalformedSourceDataError(f"{source_file}: expected one attack-flow, got {len(flows)}")
    flow = flows[0]
    start_refs = flow.get("start_refs")
    if not start_refs:
        raise MissingRequiredFieldError(f"{source_file}: attack-flow has no start_refs")
    flow_name = flow.get("name") or document_id

    # Validate every graph reference up front: dangling references are malformed data.
    for ref in start_refs:
        if ref not in by_id or by_id[ref]["type"] not in FLOW_NODE_TYPES:
            raise MalformedSourceDataError(f"{source_file}: start_ref {ref} is not a flow node")
    for obj in objects:
        if obj["type"] in FLOW_NODE_TYPES:
            for ref in _successors(obj):
                if ref not in by_id:
                    raise MalformedSourceDataError(
                        f"{source_file}: {obj['id']} references missing object {ref}"
                    )

    actions = {o["id"]: _parse_action(o) for o in objects if o["type"] == "attack-action"}
    stats = FlowDocumentStats(
        actions=len(actions),
        attack_actions=sum(a.technique_kind == "attack" for a in actions.values()),
        non_attack_actions=sum(a.technique_kind == "non_attack" for a in actions.values()),
        missing_technique_actions=sum(a.technique_kind == "missing" for a in actions.values()),
    )
    group = source_group_for(flow_name)
    scope = flow.get("scope")
    common = {
        "document_id": document_id,
        "source_group": group,
        "source_file": source_file,
        "source_sha256": source_sha256,
        "source_version": source_version,
        "flow_id": flow["id"],
        "flow_name": flow_name,
        "scope": scope,
    }

    reached: set[str] = set()
    sequences: list[FlowSequence] = []
    for node_path, cycle in _enumerate_paths(start_refs, by_id, max_paths, stats):
        reached.update(node_path)
        stats.paths += 1
        stats.cycle_truncated_paths += int(cycle)
        action_ids = [n for n in node_path if n in actions]
        steps: list[FlowSequenceStep] = []
        gap = 0
        for action_id in action_ids:
            action = actions[action_id]
            if action.technique_id is None:
                gap += 1
                continue
            steps.append(
                FlowSequenceStep(
                    position=len(steps),
                    action_id=action_id,
                    technique_id=action.technique_id,
                    tactic_id=action.tactic_id,
                    gap_before=gap,
                )
            )
            gap = 0
        if not steps:
            stats.paths_without_attack_techniques += 1
            continue
        sequences.append(
            FlowSequence(
                sequence_id=f"{document_id}::p{stats.paths - 1:05d}",
                path_index=stats.paths - 1,
                action_ids=action_ids,
                steps=steps,
                cycle_truncated=cycle,
                **common,
            )
        )
    stats.unreachable_actions = sum(1 for a in actions if a not in reached)

    excluded = scope in excluded_scopes
    return AttackFlowDocument(
        **common,
        excluded=excluded,
        exclusion_reason=f"scope '{scope}' is excluded by policy" if excluded else None,
        actions=list(actions.values()),
        sequences=sequences,
        stats=stats,
    )


def _enumerate_paths(
    start_refs: list[str],
    by_id: dict[str, dict[str, Any]],
    max_paths: int,
    stats: FlowDocumentStats,
) -> Iterator[tuple[list[str], bool]]:
    """Yield (node path, cycle_truncated) for every maximal path, in source order.

    Iterative DFS; successors are pushed in reverse so they are visited in the order
    they appear in the source document.
    """
    emitted = 0
    for start in start_refs:
        stack: list[tuple[str, list[str], bool]] = [(start, [start], False)]
        while stack:
            node_id, path, cycle = stack.pop()
            successors = _successors(by_id[node_id])
            fresh = [s for s in successors if s not in path]
            # Any edge back into the current path is a cycle: dropped, and the path flagged.
            cycle = cycle or len(fresh) != len(successors)
            if not fresh:
                emitted += 1
                yield path, cycle
                if emitted >= max_paths:
                    stats.truncated_at_max_paths = True
                    return
                continue
            for succ in reversed(fresh):
                stack.append((succ, [*path, succ], cycle))


def load_attack_flow_file(
    path: Path,
    source_version: str,
    max_paths: int = DEFAULT_MAX_PATHS_PER_DOCUMENT,
    excluded_scopes: frozenset[str] = DEFAULT_EXCLUDED_SCOPES,
) -> AttackFlowDocument:
    """Read and parse one Attack Flow STIX JSON file."""
    raw = path.read_bytes()
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedSourceDataError(f"{path.name} is not valid JSON") from exc
    return parse_attack_flow(
        bundle,
        document_id=path.stem,
        source_file=path.name,
        source_sha256=sha256_bytes(raw),
        source_version=source_version,
        max_paths=max_paths,
        excluded_scopes=excluded_scopes,
    )
