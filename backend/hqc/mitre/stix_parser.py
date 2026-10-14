"""Normalise an official ATT&CK Enterprise STIX 2.1 bundle into :class:`KnowledgeBaseData`.

Rules (all deterministic):
- Techniques come from ``attack-pattern`` objects with a ``mitre-attack`` external ID.
  Revoked and deprecated techniques are kept (flagged) so old IDs can be resolved.
- Tactics come from the Enterprise ``x-mitre-matrix`` in matrix order.
- Mitigations are ``course-of-action`` objects with ``M####`` IDs; legacy deprecated
  course-of-action objects are skipped and counted.
- Relationships marked revoked or deprecated are ignored.
- Detection coverage: detection strategy --detects--> technique; strategy analytics
  reference data components via ``x_mitre_log_source_references``.
- Missing required fields raise :class:`MissingRequiredFieldError`; structural
  problems raise :class:`MalformedSourceDataError`. Nothing is guessed.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from hqc.common.errors import MalformedSourceDataError, MissingRequiredFieldError
from hqc.common.schemas.attack import (
    ATTACKDataComponent,
    ATTACKMitigation,
    ATTACKTactic,
    ATTACKTechnique,
)
from hqc.common.schemas.base import TECHNIQUE_ID_REGEX
from hqc.mitre.models import KBMetadata, KBRelationship, KnowledgeBaseData

STIXObject = dict[str, Any]
ATTACK_SOURCE_NAME = "mitre-attack"
ATTACK_KILL_CHAIN = "mitre-attack"
_TECHNIQUE_RE = re.compile(TECHNIQUE_ID_REGEX)
_MITIGATION_RE = re.compile(r"^M\d{4}$")


def _require(obj: STIXObject, key: str) -> Any:
    value = obj.get(key)
    if value is None or value == "":
        raise MissingRequiredFieldError(f"{obj.get('type')} {obj.get('id')} is missing '{key}'")
    return value


def _attack_ref(obj: STIXObject) -> dict[str, Any] | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == ATTACK_SOURCE_NAME:
            return ref
    return None


def attack_external_id(obj: STIXObject, required: bool = True) -> str | None:
    """Return the ATT&CK external ID (e.g. T1059, TA0002, M1036, DET0001)."""
    ref = _attack_ref(obj)
    ext = ref.get("external_id") if ref else None
    if not ext and required:
        raise MissingRequiredFieldError(
            f"{obj.get('type')} {obj.get('id')} has no mitre-attack external_id"
        )
    return str(ext) if ext else None


def _is_inactive(obj: STIXObject) -> bool:
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


class _Bundle:
    """Indexed view over the bundle's objects."""

    def __init__(self, bundle: dict[str, Any]) -> None:
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise MalformedSourceDataError("ATT&CK source is not a STIX bundle")
        objects = bundle.get("objects")
        if not isinstance(objects, list) or not objects:
            raise MalformedSourceDataError("STIX bundle has no 'objects' list")
        self.by_id: dict[str, STIXObject] = {}
        self.by_type: dict[str, list[STIXObject]] = defaultdict(list)
        for obj in objects:
            if not isinstance(obj, dict) or "type" not in obj or "id" not in obj:
                raise MalformedSourceDataError("STIX object without 'type'/'id'")
            self.by_id[obj["id"]] = obj
            self.by_type[obj["type"]].append(obj)

    def single(self, stix_type: str) -> STIXObject:
        found = self.by_type.get(stix_type, [])
        if len(found) != 1:
            raise MalformedSourceDataError(f"Expected exactly one {stix_type}, found {len(found)}")
        return found[0]

    def active_relationships(self, relationship_type: str) -> Iterable[STIXObject]:
        for rel in self.by_type.get("relationship", []):
            if rel.get("relationship_type") == relationship_type and not _is_inactive(rel):
                yield rel


def _parse_tactics(bundle: _Bundle) -> list[ATTACKTactic]:
    matrix = bundle.single("x-mitre-matrix")
    tactics: list[ATTACKTactic] = []
    for order, ref in enumerate(_require(matrix, "tactic_refs")):
        obj = bundle.by_id.get(ref)
        if obj is None:
            raise MalformedSourceDataError(f"Matrix references unknown tactic {ref}")
        tactics.append(
            ATTACKTactic(
                tactic_id=attack_external_id(obj) or "",
                name=_require(obj, "name"),
                shortname=_require(obj, "x_mitre_shortname"),
                order=order,
                description=obj.get("description"),
            )
        )
    return tactics


def _parse_data_components(bundle: _Bundle) -> dict[str, ATTACKDataComponent]:
    """Map data-component STIX id -> component (active components only)."""
    components: dict[str, ATTACKDataComponent] = {}
    for obj in bundle.by_type.get("x-mitre-data-component", []):
        if _is_inactive(obj):
            continue
        components[obj["id"]] = ATTACKDataComponent(
            component_id=attack_external_id(obj) or "", name=_require(obj, "name")
        )
    return components


def _detection_index(
    bundle: _Bundle, components: dict[str, ATTACKDataComponent]
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """technique STIX id -> (detection strategy IDs, data component IDs)."""
    strategies: dict[str, set[str]] = defaultdict(set)
    data_components: dict[str, set[str]] = defaultdict(set)
    for rel in bundle.active_relationships("detects"):
        strategy = bundle.by_id.get(rel["source_ref"])
        if strategy is None or strategy.get("type") != "x-mitre-detection-strategy":
            continue
        if _is_inactive(strategy):
            continue
        technique_ref = rel["target_ref"]
        det_id = attack_external_id(strategy)
        if det_id:
            strategies[technique_ref].add(det_id)
        for analytic_ref in strategy.get("x_mitre_analytic_refs") or []:
            analytic = bundle.by_id.get(analytic_ref)
            if analytic is None or _is_inactive(analytic):
                continue
            for log_ref in analytic.get("x_mitre_log_source_references") or []:
                component = components.get(log_ref.get("x_mitre_data_component_ref", ""))
                if component is not None:
                    data_components[technique_ref].add(component.component_id)
    return strategies, data_components


def parse_attack_bundle(
    bundle: dict[str, Any],
    expected_version: str,
    source_url: str | None = None,
    source_sha256: str | None = None,
) -> KnowledgeBaseData:
    """Normalise an ATT&CK Enterprise STIX bundle.

    Raises:
        UnsupportedAttackVersionError: is never raised here; a version mismatch between
            the bundle and ``expected_version`` raises MalformedSourceDataError because
            the file does not contain what it claims to.
    """
    view = _Bundle(bundle)
    collection = view.single("x-mitre-collection")
    version = str(_require(collection, "x_mitre_version"))
    if version != expected_version:
        raise MalformedSourceDataError(
            f"Bundle declares ATT&CK {version}, expected {expected_version}"
        )
    skipped: Counter[str] = Counter()

    tactics = _parse_tactics(view)
    shortname_to_tactic = {t.shortname: t.tactic_id for t in tactics}
    components = _parse_data_components(view)
    det_index, dc_index = _detection_index(view, components)

    # --- techniques -------------------------------------------------------------
    stix_to_tid: dict[str, str] = {}
    raw_techniques: dict[str, STIXObject] = {}
    for obj in view.by_type.get("attack-pattern", []):
        tid = attack_external_id(obj) or ""
        if not _TECHNIQUE_RE.match(tid):
            raise MalformedSourceDataError(f"attack-pattern {obj['id']} has invalid ID {tid!r}")
        if tid in raw_techniques:
            raise MalformedSourceDataError(f"Duplicate technique ID {tid}")
        stix_to_tid[obj["id"]] = tid
        raw_techniques[tid] = obj

    parent_of: dict[str, str] = {}
    revoked_by: dict[str, str] = {}
    relationships: list[KBRelationship] = []
    for rel in view.active_relationships("subtechnique-of"):
        child, parent = stix_to_tid.get(rel["source_ref"]), stix_to_tid.get(rel["target_ref"])
        if child is None or parent is None:
            skipped["subtechnique_of_unresolved"] += 1
            continue
        parent_of[child] = parent
        relationships.append(
            KBRelationship(relationship_type="subtechnique-of", source_id=child, target_id=parent)
        )
    for rel in view.by_type.get("relationship", []):
        if rel.get("relationship_type") != "revoked-by":
            continue
        old, new = stix_to_tid.get(rel["source_ref"]), stix_to_tid.get(rel["target_ref"])
        if old is None or new is None:
            continue  # revoked-by between non-technique objects (groups, software)
        revoked_by[old] = new
        relationships.append(
            KBRelationship(relationship_type="revoked-by", source_id=old, target_id=new)
        )

    # --- mitigations -------------------------------------------------------------
    mitigation_objs: dict[str, STIXObject] = {}
    stix_to_mid: dict[str, str] = {}
    for obj in view.by_type.get("course-of-action", []):
        mid = attack_external_id(obj, required=False) or ""
        if _is_inactive(obj) or not _MITIGATION_RE.match(mid):
            skipped["course_of_action_legacy_or_inactive"] += 1
            continue
        mitigation_objs[mid] = obj
        stix_to_mid[obj["id"]] = mid

    techniques_of_mitigation: dict[str, set[str]] = defaultdict(set)
    mitigations_of_technique: dict[str, set[str]] = defaultdict(set)
    for rel in view.active_relationships("mitigates"):
        rel_mid = stix_to_mid.get(rel["source_ref"])
        rel_tid = stix_to_tid.get(rel["target_ref"])
        if rel_mid is None or rel_tid is None:
            skipped["mitigates_unresolved"] += 1
            continue
        techniques_of_mitigation[rel_mid].add(rel_tid)
        mitigations_of_technique[rel_tid].add(rel_mid)
        relationships.append(
            KBRelationship(relationship_type="mitigates", source_id=rel_mid, target_id=rel_tid)
        )

    techniques: list[ATTACKTechnique] = []
    for tid in sorted(raw_techniques):
        obj = raw_techniques[tid]
        inactive = _is_inactive(obj)
        tactic_ids: list[str] = []
        for phase in obj.get("kill_chain_phases") or []:
            if phase.get("kill_chain_name") != ATTACK_KILL_CHAIN:
                continue
            tactic = shortname_to_tactic.get(phase.get("phase_name", ""))
            if tactic is None:
                if not inactive:
                    raise MalformedSourceDataError(
                        f"{tid} references unknown tactic {phase.get('phase_name')!r}"
                    )
                skipped["inactive_technique_unknown_tactic"] += 1
                continue
            if tactic not in tactic_ids:
                tactic_ids.append(tactic)
        is_sub = bool(obj.get("x_mitre_is_subtechnique", "." in tid))
        parent = parent_of.get(tid) if is_sub else None
        if is_sub and parent is None:
            if not inactive:
                raise MissingRequiredFieldError(f"Active sub-technique {tid} has no parent link")
            # Revoked/deprecated sub-techniques may lack the relationship; ATT&CK sub-technique
            # IDs are structurally Txxxx.yyy, so the parent is Txxxx (recorded as skipped).
            parent = tid.split(".", 1)[0]
            skipped["inactive_subtechnique_parent_from_id"] += 1
        ref = _attack_ref(obj) or {}
        try:
            techniques.append(
                ATTACKTechnique(
                    technique_id=tid,
                    name=_require(obj, "name"),
                    tactic_ids=tactic_ids,
                    is_subtechnique=is_sub,
                    parent_id=parent,
                    description=obj.get("description"),
                    platforms=sorted(obj.get("x_mitre_platforms") or []),
                    mitigation_ids=sorted(mitigations_of_technique.get(tid, set())),
                    detection_strategy_ids=sorted(det_index.get(obj["id"], set())),
                    data_component_ids=sorted(dc_index.get(obj["id"], set())),
                    deprecated=bool(obj.get("x_mitre_deprecated")),
                    revoked=bool(obj.get("revoked")),
                    revoked_by=revoked_by.get(tid),
                    stix_id=obj["id"],
                    url=ref.get("url"),
                    attack_version=version,
                )
            )
        except ValidationError as exc:
            raise MalformedSourceDataError(f"Technique {tid} failed validation: {exc}") from exc

    mitigations = [
        ATTACKMitigation(
            mitigation_id=mid,
            name=_require(mitigation_objs[mid], "name"),
            description=mitigation_objs[mid].get("description"),
            technique_ids=sorted(techniques_of_mitigation.get(mid, set())),
        )
        for mid in sorted(mitigation_objs)
    ]
    data_components = sorted(components.values(), key=lambda c: c.component_id)
    relationships.sort(key=lambda r: (r.relationship_type, r.source_id, r.target_id))

    active = [t for t in techniques if t.is_active]
    metadata = KBMetadata(
        attack_version=version,
        attack_spec_version=collection.get("x_mitre_attack_spec_version"),
        collection_name=_require(collection, "name"),
        collection_modified=_require(collection, "modified"),
        source_url=source_url,
        source_sha256=source_sha256,
        counts={
            "tactics": len(tactics),
            "techniques_total": len(techniques),
            "techniques_active": len(active),
            "techniques_active_parent": sum(1 for t in active if not t.is_subtechnique),
            "techniques_active_sub": sum(1 for t in active if t.is_subtechnique),
            "techniques_revoked": sum(1 for t in techniques if t.revoked),
            "techniques_deprecated": sum(1 for t in techniques if t.deprecated),
            "mitigations": len(mitigations),
            "data_components": len(data_components),
            "relationships": len(relationships),
        },
        skipped=dict(sorted(skipped.items())),
    )
    return KnowledgeBaseData(
        metadata=metadata,
        tactics=tactics,
        techniques=techniques,
        mitigations=mitigations,
        data_components=data_components,
        relationships=relationships,
    )
