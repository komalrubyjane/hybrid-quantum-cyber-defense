"""Builders for small, hand-made STIX bundles (TEST FIXTURES, not MITRE data).

The ATT&CK-like bundle mimics the structure of the official Enterprise bundle with a
handful of objects so every parser rule can be exercised offline.
"""

from __future__ import annotations

import copy
from typing import Any

TEST_VERSION = "0.1"

Obj = dict[str, Any]


def _ref(ext_id: str, url: str | None = None) -> list[Obj]:
    ref: Obj = {"source_name": "mitre-attack", "external_id": ext_id}
    if url:
        ref["url"] = url
    return [ref]


def _tactic(stix_id: str, ext: str, name: str, short: str) -> Obj:
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name,
        "x_mitre_shortname": short,
        "external_references": _ref(ext),
    }


def _technique(
    stix_id: str, ext: str, name: str, phases: list[str], sub: bool = False, **extra: Any
) -> Obj:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": f"Test description of {name}.",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
        "x_mitre_is_subtechnique": sub,
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_deprecated": False,
        "revoked": False,
        "external_references": _ref(ext, f"https://attack.mitre.org/techniques/{ext}"),
        **extra,
    }


def _rel(rid: str, rtype: str, src: str, tgt: str, **extra: Any) -> Obj:
    return {
        "type": "relationship",
        "id": rid,
        "relationship_type": rtype,
        "source_ref": src,
        "target_ref": tgt,
        **extra,
    }


def attack_bundle(version: str = TEST_VERSION) -> Obj:
    """A minimal ATT&CK Enterprise-like bundle.

    Techniques: T1059 (parent), T1059.001, T1059.004 (subs), T1003 (cred access, two
    tactics), T1086 (revoked -> T1059.001), T1999 (deprecated), T1059.999 (revoked sub
    without subtechnique-of link).
    """
    objects: list[Obj] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--1",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": version,
            "x_mitre_attack_spec_version": "3.3.0",
            "modified": "2026-01-01T00:00:00.000Z",
        },
        {
            "type": "x-mitre-matrix",
            "id": "x-mitre-matrix--1",
            "name": "Enterprise ATT&CK",
            # Matrix order intentionally differs from tactic-ID order.
            "tactic_refs": ["x-mitre-tactic--exec", "x-mitre-tactic--cred", "x-mitre-tactic--disc"],
        },
        _tactic("x-mitre-tactic--disc", "TA0007", "Discovery", "discovery"),
        _tactic("x-mitre-tactic--exec", "TA0002", "Execution", "execution"),
        _tactic("x-mitre-tactic--cred", "TA0006", "Credential Access", "credential-access"),
        _technique(
            "attack-pattern--t1059", "T1059", "Command and Scripting Interpreter", ["execution"]
        ),
        _technique("attack-pattern--t1059-001", "T1059.001", "PowerShell", ["execution"], sub=True),
        _technique("attack-pattern--t1059-004", "T1059.004", "Unix Shell", ["execution"], sub=True),
        _technique(
            "attack-pattern--t1003",
            "T1003",
            "OS Credential Dumping",
            ["credential-access", "discovery"],
        ),
        _technique(
            "attack-pattern--t1086", "T1086", "PowerShell (old)", ["execution"], revoked=True
        ),
        _technique(
            "attack-pattern--t1999",
            "T1999",
            "Old Technique",
            ["defense-evasion"],  # tactic no longer in the matrix: allowed for inactive objects
            x_mitre_deprecated=True,
        ),
        _technique(
            "attack-pattern--t1059-999",
            "T1059.999",
            "Revoked Sub",
            ["execution"],
            sub=True,
            revoked=True,
        ),
        {
            "type": "course-of-action",
            "id": "course-of-action--m1038",
            "name": "Execution Prevention",
            "description": "Block execution.",
            "external_references": _ref("M1038"),
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--m1026",
            "name": "Privileged Account Management",
            "external_references": _ref("M1026"),
        },
        {  # legacy pre-2018 mitigation with a technique-style ID
            "type": "course-of-action",
            "id": "course-of-action--legacy",
            "name": "Legacy Mitigation",
            "x_mitre_deprecated": True,
            "external_references": _ref("T1086"),
        },
        {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--dc1",
            "name": "Process Creation",
            "external_references": _ref("DC0032"),
        },
        {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--an1",
            "name": "AN0001",
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": "x-mitre-data-component--dc1", "name": "log"}
            ],
            "external_references": _ref("AN0001"),
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--det1",
            "name": "Detect credential dumping",
            "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
            "external_references": _ref("DET0001"),
        },
        _rel(
            "relationship--s1",
            "subtechnique-of",
            "attack-pattern--t1059-001",
            "attack-pattern--t1059",
        ),
        _rel(
            "relationship--s2",
            "subtechnique-of",
            "attack-pattern--t1059-004",
            "attack-pattern--t1059",
        ),
        _rel(
            "relationship--m1", "mitigates", "course-of-action--m1038", "attack-pattern--t1059-004"
        ),
        _rel("relationship--m2", "mitigates", "course-of-action--m1038", "attack-pattern--t1059"),
        _rel("relationship--m3", "mitigates", "course-of-action--m1026", "attack-pattern--t1003"),
        _rel(  # deprecated relationship must be ignored
            "relationship--m4",
            "mitigates",
            "course-of-action--m1026",
            "attack-pattern--t1059",
            x_mitre_deprecated=True,
        ),
        _rel(
            "relationship--r1", "revoked-by", "attack-pattern--t1086", "attack-pattern--t1059-001"
        ),
        _rel(
            "relationship--d1",
            "detects",
            "x-mitre-detection-strategy--det1",
            "attack-pattern--t1003",
        ),
    ]
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


def mutate(bundle: Obj, stix_id: str, **changes: Any) -> Obj:
    """Deep-copied bundle with fields of one object changed (None deletes the key)."""
    out = copy.deepcopy(bundle)
    for obj in out["objects"]:
        if obj["id"] == stix_id:
            for key, value in changes.items():
                if value is None:
                    obj.pop(key, None)
                else:
                    obj[key] = value
    return out


# --- Attack Flow --------------------------------------------------------------------


def action(aid: str, technique: str | None, effects: list[str] | None = None, **extra: Any) -> Obj:
    obj: Obj = {"type": "attack-action", "id": f"attack-action--{aid}", "name": f"step {aid}"}
    if technique is not None:
        obj["technique_id"] = technique
    if effects:
        obj["effect_refs"] = [_node_id(e) for e in effects]
    obj.update(extra)
    return obj


def operator(oid: str, op: str, effects: list[str]) -> Obj:
    return {
        "type": "attack-operator",
        "id": f"attack-operator--{oid}",
        "operator": op,
        "effect_refs": [_node_id(e) for e in effects],
    }


def condition(cid: str, on_true: list[str], on_false: list[str] | None = None) -> Obj:
    obj: Obj = {
        "type": "attack-condition",
        "id": f"attack-condition--{cid}",
        "description": f"condition {cid}",
        "on_true_refs": [_node_id(e) for e in on_true],
    }
    if on_false:
        obj["on_false_refs"] = [_node_id(e) for e in on_false]
    return obj


def _node_id(short: str) -> str:
    """'a1' -> attack-action--a1, 'op:x' -> attack-operator--x, 'cond:y' -> condition."""
    if short.startswith("op:"):
        return f"attack-operator--{short[3:]}"
    if short.startswith("cond:"):
        return f"attack-condition--{short[5:]}"
    return f"attack-action--{short}"


def flow_bundle(
    nodes: list[Obj], starts: list[str], name: str = "Test Flow", scope: str = "incident"
) -> Obj:
    flow = {
        "type": "attack-flow",
        "id": "attack-flow--test",
        "name": name,
        "scope": scope,
        "start_refs": [_node_id(s) for s in starts],
    }
    return {"type": "bundle", "id": "bundle--flow", "objects": [flow, *nodes]}
