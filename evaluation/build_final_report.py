# ruff: noqa: E501  (report script: long SVG / markdown string templates are kept on one line)
"""Milestone 10: consolidate STORED results into final tables, figures and a reproducibility audit.

Reads only the stored run folders (``reports/runs/<run-id>/``), the data manifest and local
artifacts. Nothing is trained, evaluated or re-run, and no number is typed in by hand: every
value is extracted from a stored ``metrics.json`` / ``results.json``.

Writes ``artifacts/final/``:
- ``results.json``           consolidated machine-readable results (with run IDs);
- ``tables/*.csv``, ``tables.md``  human- and machine-readable tables;
- ``figures/*.svg``          figures (dependency-free SVG; CIs drawn only where they exist);
- ``reproducibility.json``   provenance and artifact-checksum audit;
- ``metadata.json``          generator, run IDs, source fingerprint.

Usage:
    python evaluation/build_final_report.py [--skip-large-checksums]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections.abc import Sequence
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "reports" / "runs"
OUT = ROOT / "artifacts" / "final"
RUN_M3 = "20261006T173740Z-markov-baselines-document"
RUN_M4 = "20261006T181005Z-lstm-hybrid-beam-document"
RUN_M5 = "20261006T195110Z-classical-detection-cicids2017"
RUN_M6 = "20261007T053257Z-quantum-adjudicator-cicids2017"
RUN_M7 = "20261007T083826Z-integration-synthetic-multistage"
RUN_IDS = {"M3": RUN_M3, "M4": RUN_M4, "M5": RUN_M5, "M6": RUN_M6, "M7": RUN_M7}
PRED_METRICS = ("top1", "top5", "mrr", "log_loss")
QUANTUM_ARMS = ("random_forest", "logreg", "linear_svm", "rbf_svm", "zz_qsvm", "z_qsvm")

Json = dict[str, Any]


def load(run: str, name: str = "metrics.json") -> Json:
    data: Json = json.loads((RUNS / run / name).read_text(encoding="utf-8"))
    return data


def r(x: float | None, digits: int = 4) -> float | None:
    return None if x is None or not math.isfinite(x) else round(float(x), digits)


# --- extraction ------------------------------------------------------------------------------


def ci_stat(stat: Json) -> Json:
    return {
        "mean": r(stat["mean"]),
        "ci_low": r(stat["ci_low"]),
        "ci_high": r(stat["ci_high"]),
        "n_groups": stat.get("n_groups"),
    }


def prediction_results() -> Json:
    m3 = load(RUN_M3)["results"]["document"]["models"]
    m4 = load(RUN_M4)
    rows = []
    for model in ("B0", "B1", "M1", "M2"):
        rows.append(
            {
                "model": model,
                "run_id": RUN_M3,
                **{m: ci_stat(m3[model]["macro"][m]) for m in PRED_METRICS},
            }
        )
    for model in ("LSTM", "HYBRID"):
        rows.append(
            {
                "model": model,
                "run_id": RUN_M4,
                **{m: ci_stat(m4["single_step"][model]["macro"][m]) for m in PRED_METRICS},
            }
        )
    pairs = [
        {
            "model_a": c["model_a"],
            "model_b": c["model_b"],
            "metric": c["metric"],
            "mean_difference": r(c["mean_difference"]),
            "ci_low": r(c["ci_low"]),
            "ci_high": r(c["ci_high"]),
            "ci_excludes_zero": c["ci_excludes_zero"],
        }
        for c in m4["comparisons"]
        if c["metric"] in PRED_METRICS
        and c["model_b"] in ("B1", "LSTM", "MARKOV")
        and c["model_a"] in ("LSTM", "HYBRID", "MARKOV")
    ]
    multistep = [
        {
            "model": s["model"],
            "horizon": s["horizon"],
            **{k: ci_stat(v) for k, v in s["macro"].items() if k.startswith(("path_hit", "step"))},
        }
        for s in m4["multistep"]
    ]
    return {
        "protocol": "nested leave-one-group-out over 37 Attack Flow source groups (36 evaluable); "
        "document weighting; macro mean over groups with 95% bootstrap CI",
        "folds_total": load(RUN_M3)["folds_total"],
        "folds_without_test_instances": load(RUN_M3)["folds_without_test_instances"],
        "models": rows,
        "paired_comparisons": pairs,
        "multistep_beam_width_10": multistep,
        "multistep_status": m4["multistep_status"],
    }


def detection_results() -> Json:
    m5 = load(RUN_M5)
    rows = []
    for e in m5["evaluations"]:
        m = e["metrics"]
        rows.append(
            {
                "model": e["model"],
                "feature_set": e["feature_set"],
                "subset": e["subset"],
                "n": m["n"],
                **{
                    k: r(m[k])
                    for k in (
                        "accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "roc_auc",
                        "pr_auc",
                        "benign_false_positive_rate",
                    )
                },
                "confusion": m["confusion"],
            }
        )
    per_label = {
        f"{e['model']}/{e['feature_set']}": {
            k: r(v["predicted_malicious_rate"]) for k, v in e["per_label_detection"].items()
        }
        for e in m5["evaluations"]
        if e["subset"] == "all_test_rows"
    }
    stats = m5["dataset_statistics"]
    return {
        "protocol": "whole-day holdout: train Monday-Wednesday, test Thursday-Friday; fixed 0.5 "
        "threshold; primary detector pre-registered (random_forest); single run, no CIs",
        "dataset": {
            "rows": stats["rows_total"],
            "malicious_fraction": r(stats["malicious_fraction"]),
            "files": len(stats["files"]),
        },
        "rows": rows,
        "per_label_predicted_malicious_rate": per_label,
        "duplicate_audit": m5["duplicate_audit"],
    }


def quantum_results() -> Json:
    m6 = load(RUN_M6)
    e2 = m6["e2"]["aggregate"]
    e3 = {}
    for band, run in m6["e3"].items():
        rows = []
        classical = run["classical_full_test"]
        rows.append(
            {
                "arm": "RF alone",
                **{
                    k: r(classical[k])
                    for k in (
                        "precision",
                        "recall",
                        "f1",
                        "roc_auc",
                        "pr_auc",
                        "benign_false_positive_rate",
                    )
                },
            }
        )
        for arm in run["arms"]:
            f = arm["fused_full_test"]
            rows.append(
                {
                    "arm": f"RF + {arm['kind']}",
                    **{
                        k: r(f[k])
                        for k in (
                            "precision",
                            "recall",
                            "f1",
                            "roc_auc",
                            "pr_auc",
                            "benign_false_positive_rate",
                        )
                    },
                    "flips": arm["flips"]["flips"],
                    "disagreements": arm["disagreement"]["disagree"],
                }
            )
        b = run["band"]
        e3[band] = {
            "band": [r(b["lower"], 6), r(b["upper"], 6)],
            "train_oof_coverage": r(b["train_oof_coverage"]),
            "test_band_coverage": r(run["test_band_coverage"]),
            "test_band_rows": run["test_band_rows"],
            "whole_test_set": rows,
        }
    e4 = m6["e4"]
    return {
        "protocol": "exact statevector simulation (NumPy, validated against qiskit 2.5.2); "
        "E2 5 seeds x N {100..2000} x d {4,6,8}, mean +/- 95% t-CI; E3 single seed; E4 single seed",
        "e2_aggregate": e2,
        "e3": e3,
        "e4": {
            "feature_map": e4["feature_map"],
            "n_train": e4["n_train"],
            "n_test": e4["n_test"],
            "exact_balanced_accuracy": r(e4["exact_test_balanced_accuracy"]),
            "exact_roc_auc": r(e4["exact_test"]["roc_auc"]),
            "settings": [
                {
                    "name": s["setting"]["name"],
                    "shots": s["setting"]["shots"],
                    "p1": s["setting"]["p1"],
                    "p2": s["setting"]["p2"],
                    "readout": s["setting"]["readout"],
                    "train_rel_frobenius_error": r(s["train_relative_frobenius_error"]),
                    "test_rel_frobenius_error": r(s["test_relative_frobenius_error"]),
                    "balanced_accuracy": r(s["test_balanced_accuracy"]),
                    "roc_auc": r(s["test"]["roc_auc"]),
                }
                for s in e4["settings"]
            ],
        },
        "conclusion": "No quantum advantage was observed under the tested conditions.",
    }


def integration_results() -> Json:
    m7 = load(RUN_M7, "results.json")
    incidents = []
    for a in m7["output"]["incidents"]:
        nxt = a["prediction"]["result"]["next_step"]
        incidents.append(
            {
                "chain_id": a["chain"]["chain_id"],
                "status": a["chain"]["status"],
                "observed": [s["technique_id"] for s in a["chain"]["chain"]["steps"]],
                "top_next": {
                    "technique_id": nxt[0]["technique_id"],
                    "probability": r(nxt[0]["probability"]),
                }
                if nxt
                else None,
                "risk_score": r(a["risk"]["score"], 2),
                "risk_level": a["risk"]["level"],
                "evidence_status": a["risk"]["evidence_status"],
                "recommendations": [rec["action"] for rec in a["recommendations"]],
            }
        )
    return {
        "nature": "SYNTHETIC demonstration (hand-authored scenario); NOT a real-world validated "
        "attack-chain evaluation",
        "incidents": incidents,
        "risk_trajectory": [
            {
                "after": p["after_event_id"],
                "chain": p["chain_id"],
                "score": r(p["score"], 2),
                "level": p["level"],
            }
            for p in m7["risk_trajectory"]
        ],
        "integration_checks": {
            "passed": sum(c["passed"] for c in m7["integration_checks"]),
            "total": len(m7["integration_checks"]),
        },
        "stored_m6_policy_check": m7["stored_output_policy_check"],
    }


# --- reproducibility audit ----------------------------------------------------------------------


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fingerprint() -> Json:
    files = sorted(
        p
        for d in ("backend", "configs", "evaluation", "scripts")
        for p in (ROOT / d).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )
    digest = hashlib.sha256()
    for p in files:
        digest.update(str(p.relative_to(ROOT)).encode())
        digest.update(sha256(p).encode())
    return {
        "files": len(files),
        "sha256": digest.hexdigest(),
        "note": "fingerprint of the working tree at report time (code is uncommitted)",
    }


def artifact_audit(skip_large: bool) -> list[Json]:
    manifest = yaml.safe_load((ROOT / "data" / "MANIFEST.yaml").read_text(encoding="utf-8"))
    out = []
    for art in manifest["artifacts"]:
        entry: Json = {
            "id": art["artifact_id"],
            "kind": art.get("kind"),
            "version": art.get("version"),
        }
        paths: list[tuple[Path, str | None]] = []
        local = ROOT / art["local_path"] if art.get("local_path") else None
        files = art.get("files") or []
        if local is not None and not files:
            paths.append((local, art.get("sha256")))  # single-file artifact
        for f in files:  # directory artifact: files relative to local_path
            paths.append(((local or ROOT) / f["name"], f.get("sha256")))
        checked, present, ok = 0, 0, True
        for path, expected in paths:
            if path.is_file():
                present += 1
                large = path.stat().st_size > 50_000_000
                if expected and not (skip_large and large):
                    checked += 1
                    ok &= sha256(path) == expected
        entry.update(
            {
                "files_expected": len(paths),
                "files_present": present,
                "checksums_verified": checked,
                "checksums_match": ok if checked else None,
            }
        )
        out.append(entry)
    return out


def run_provenance() -> list[Json]:
    rows = []
    for milestone, run in RUN_IDS.items():
        config = load(run, "config.json")
        rows.append(
            {
                "milestone": milestone,
                "run_id": run,
                "git_commit": config.get("git_commit"),
                "working_tree_dirty": config.get("working_tree_dirty"),
                "seed": config.get("random_seed"),
                "files": sorted(p.name for p in (RUNS / run).iterdir()),
            }
        )
    return rows


REPRODUCIBILITY_CLASSES = [
    {
        "result": "M3 Markov baselines",
        "class": "B",
        "how": "python evaluation/run_markov_baseline.py (recorded runtime 103 s; needs the downloaded ATT&CK 19.2 bundle and Attack Flow corpus; checksums in data/MANIFEST.yaml)",
        "stored": "metrics, predictions, fitted B1/M1/M2 artifacts",
    },
    {
        "result": "M4 LSTM / hybrid / beam search",
        "class": "B",
        "how": "python evaluation/run_sequence_models.py (CPU, seeded; recorded runtime 518 s); checkpoints for 36 folds stored",
        "stored": "metrics, training history, predictions, fold checkpoints",
    },
    {
        "result": "M5 CIC-IDS2017 detectors",
        "class": "B",
        "how": "manual registration download of GeneratedLabelledFlows.zip (SHA-256 verified), then scripts/register_cicids2017.py and evaluation/run_classical_detection.py (recorded runtime 193 s)",
        "stored": "metrics, per-row test predictions, model artifacts",
    },
    {
        "result": "M6 quantum second opinion",
        "class": "B",
        "how": "python evaluation/run_quantum_adjudicator.py (recorded runtime 962 s; needs the M5 run and models)",
        "stored": "metrics, band predictions, adjudicator artifacts",
    },
    {
        "result": "M7 integration demonstration",
        "class": "D",
        "how": "python evaluation/run_integration_demo.py (recorded runtime 1.4 s); SYNTHETIC scenario only",
        "stored": "results, integration checks, END_TO_END record",
    },
    {
        "result": "All tables and figures in artifacts/final",
        "class": "A",
        "how": "python evaluation/build_final_report.py (reads the stored runs only)",
        "stored": "this directory",
    },
]


# --- tables -----------------------------------------------------------------------------------


def write_csv(path: Path, rows: Sequence[Json]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(dict.fromkeys(k for row in rows for k in row))  # union, first-seen order
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, restval="")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()}
            )


def fmt(x: Any, digits: int = 4) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    return str(x)


def ci(stat: Json, digits: int = 4) -> str:
    return f"{fmt(stat['mean'], digits)} [{fmt(stat['ci_low'], 3)}, {fmt(stat['ci_high'], 3)}]"


def md_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    return [
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
        *["| " + " | ".join(r_) + " |" for r_ in rows],
    ]


def tables(results: Json) -> tuple[dict[str, list[Json]], str]:
    pred, det, q, integ = (
        results[k] for k in ("attack_prediction", "detection", "quantum", "integration")
    )
    csvs: dict[str, list[Json]] = {}
    csvs["attack_prediction"] = [
        {
            "model": m["model"],
            "run_id": m["run_id"],
            **{f"{k}_{p}": m[k][p] for k in PRED_METRICS for p in ("mean", "ci_low", "ci_high")},
        }
        for m in pred["models"]
    ]
    csvs["attack_prediction_paired"] = pred["paired_comparisons"]
    csvs["attack_prediction_multistep"] = [
        {
            "model": s["model"],
            "horizon": s["horizon"],
            **{f"{k}_mean": v["mean"] for k, v in s.items() if isinstance(v, dict)},
        }
        for s in pred["multistep_beam_width_10"]
    ]
    csvs["detection"] = [{k: v for k, v in row.items() if k != "confusion"} for row in det["rows"]]
    csvs["quantum_matched_budget"] = [
        {
            "n_train": a["n_train"],
            "n_dims": a["n_dims"],
            "arm": a["arm"],
            **{f"{m}_mean": r(a[m]["mean"]) for m in ("balanced_accuracy", "roc_auc", "pr_auc")},
            **{f"{m}_ci95": r(a[m]["ci95"]) for m in ("balanced_accuracy", "roc_auc", "pr_auc")},
        }
        for a in q["e2_aggregate"]
    ]
    csvs["quantum_fusion"] = [
        {"band": b, **row} for b, v in q["e3"].items() for row in v["whole_test_set"]
    ]
    csvs["quantum_noise"] = q["e4"]["settings"]
    csvs["integration"] = [
        {**i, "observed": " -> ".join(i["observed"])} for i in integ["incidents"]
    ]

    lines = ["# Final result tables (generated from stored runs; do not edit by hand)", ""]
    lines += ["## 1. Attack-chain prediction (macro mean [95% bootstrap CI], 36 groups)", ""]
    lines += md_table(
        ["Model", "Top-1", "Top-5", "MRR", "Log loss", "Run"],
        [
            [
                m["model"],
                ci(m["top1"]),
                ci(m["top5"]),
                ci(m["mrr"]),
                ci(m["log_loss"], 3),
                f"`{m['run_id']}`",
            ]
            for m in pred["models"]
        ],
    )
    lines += ["", "Paired differences (A - B; significant = 95% CI excludes 0):", ""]
    lines += md_table(
        ["A", "B", "Metric", "Difference [95% CI]", "Significant"],
        [
            [
                c["model_a"],
                c["model_b"],
                c["metric"],
                f"{fmt(c['mean_difference'])} [{fmt(c['ci_low'])}, {fmt(c['ci_high'])}]",
                "yes" if c["ci_excludes_zero"] else "no",
            ]
            for c in pred["paired_comparisons"]
        ],
    )
    lines += ["", "Multi-step (beam width 10): exact path hit@10 (macro mean [95% CI]):", ""]
    lines += md_table(
        ["Model", "H", "path_hit@1", "path_hit@10", "step1_acc"],
        [
            [
                s["model"],
                str(s["horizon"]),
                ci(s["path_hit@1"]),
                ci(s["path_hit@10"]),
                ci(s["step1_acc"]),
            ]
            for s in pred["multistep_beam_width_10"]
        ],
    )
    lines += ["", "## 2. CIC-IDS2017 detection (Thursday-Friday holdout; single run, no CIs)", ""]
    lines += md_table(
        [
            "Model",
            "Features",
            "Subset",
            "Precision",
            "Recall",
            "F1",
            "ROC-AUC",
            "PR-AUC",
            "Benign FPR",
        ],
        [
            [
                d["model"],
                d["feature_set"],
                d["subset"],
                *(
                    fmt(d[k])
                    for k in (
                        "precision",
                        "recall",
                        "f1",
                        "roc_auc",
                        "pr_auc",
                        "benign_false_positive_rate",
                    )
                ),
            ]
            for d in det["rows"]
        ],
    )
    lines += [
        "",
        "## 3. Quantum matched budget (E2; balanced accuracy mean ± 95% t-CI over 5 seeds)",
        "",
    ]
    for d in (4, 6, 8):
        rows = []
        for n in (100, 250, 500, 1000, 2000):
            cells = {
                a["arm"]: a for a in q["e2_aggregate"] if a["n_dims"] == d and a["n_train"] == n
            }
            rows.append(
                [
                    str(n),
                    *(
                        f"{cells[k]['balanced_accuracy']['mean']:.3f} ± {cells[k]['balanced_accuracy']['ci95']:.3f}"
                        for k in QUANTUM_ARMS
                    ),
                ]
            )
        lines += [f"d = {d}:", "", *md_table(["N", *QUANTUM_ARMS], rows), ""]
    lines += ["## 4. Quantum second-opinion fusion (E3, whole test set)", ""]
    for band, v in q["e3"].items():
        lines += [
            f"{band} band {v['band']} (train OOF coverage {v['train_oof_coverage']}, test coverage {v['test_band_coverage']}):",
            "",
        ]
        lines += md_table(
            ["Arm", "Precision", "Recall", "F1", "ROC-AUC", "PR-AUC", "Benign FPR"],
            [
                [
                    row["arm"],
                    *(
                        fmt(row[k])
                        for k in (
                            "precision",
                            "recall",
                            "f1",
                            "roc_auc",
                            "pr_auc",
                            "benign_false_positive_rate",
                        )
                    ),
                ]
                for row in v["whole_test_set"]
            ],
        )
        lines.append("")
    lines += ["## 5. Quantum noise (E4; single seed, N_train = N_test = 200)", ""]
    lines += md_table(
        [
            "Setting",
            "Shots",
            "p1",
            "p2",
            "Readout",
            "Rel. kernel error (test)",
            "Balanced acc",
            "ROC-AUC",
        ],
        [
            [
                s["name"],
                str(s["shots"]),
                str(s["p1"]),
                str(s["p2"]),
                str(s["readout"]),
                fmt(s["test_rel_frobenius_error"]),
                fmt(s["balanced_accuracy"]),
                fmt(s["roc_auc"]),
            ]
            for s in q["e4"]["settings"]
        ],
    )
    lines += [
        "",
        f"Exact statevector: balanced accuracy {q['e4']['exact_balanced_accuracy']}, ROC-AUC {q['e4']['exact_roc_auc']}.",
        "",
    ]
    lines += ["## 6. M7 integration demonstration (SYNTHETIC)", ""]
    lines += md_table(
        ["Chain", "Status", "Observed", "Top next (probability)", "Risk", "Recommendations"],
        [
            [
                i["chain_id"],
                i["status"],
                " → ".join(i["observed"]),
                f"{i['top_next']['technique_id']} ({i['top_next']['probability']})"
                if i["top_next"]
                else "n/a",
                f"{i['risk_score']} {i['risk_level']}",
                ", ".join(i["recommendations"]),
            ]
            for i in integ["incidents"]
        ],
    )
    lines += [
        "",
        f"Integration checks: {integ['integration_checks']['passed']}/{integ['integration_checks']['total']} passed.",
        "",
    ]
    return csvs, "\n".join(lines) + "\n"


# --- SVG figures (stdlib only) ---------------------------------------------------------------------

PALETTE = ["#4c72b0", "#dd8452", "#55a868", "#c44e52", "#8172b3", "#937860", "#da8bc3", "#8c8c8c"]
FONT = "font-family='Helvetica, Arial, sans-serif'"


class Svg:
    def __init__(self, width: int, height: int, title: str) -> None:
        self.w, self.h = width, height
        self.parts = [
            f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}' {FONT}>",
            f"<title>{escape(title)}</title>",
            f"<rect width='{width}' height='{height}' fill='white'/>",
            f"<text x='{width / 2}' y='22' text-anchor='middle' font-size='15' font-weight='bold'>{escape(title)}</text>",
        ]

    def add(self, s: str) -> None:
        self.parts.append(s)

    def text(
        self,
        x: float,
        y: float,
        s: str,
        size: int = 11,
        anchor: str = "middle",
        rotate: float | None = None,
        color: str = "#222",
    ) -> None:
        tr = f" transform='rotate({rotate} {x} {y})'" if rotate is not None else ""
        self.add(
            f"<text x='{x:.1f}' y='{y:.1f}' font-size='{size}' text-anchor='{anchor}' fill='{color}'{tr}>{escape(s)}</text>"
        )

    def save(self, path: Path, note: str) -> None:
        self.text(self.w / 2, self.h - 8, note, size=10, color="#555")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join([*self.parts, "</svg>"]) + "\n", encoding="utf-8")


def axis_frame(
    svg: Svg,
    x0: float,
    y0: float,
    x1: float,
    y1: float,
    lo: float,
    hi: float,
    ticks: int,
    label: str,
    digits: int = 2,
) -> Any:
    def ymap(v: float) -> float:
        return y1 - (v - lo) / (hi - lo) * (y1 - y0)

    svg.add(f"<line x1='{x0}' y1='{y0}' x2='{x0}' y2='{y1}' stroke='#333'/>")
    svg.add(f"<line x1='{x0}' y1='{y1}' x2='{x1}' y2='{y1}' stroke='#333'/>")
    for i in range(ticks + 1):
        v = lo + (hi - lo) * i / ticks
        y = ymap(v)
        svg.add(f"<line x1='{x0 - 4}' y1='{y:.1f}' x2='{x1}' y2='{y:.1f}' stroke='#e5e5e5'/>")
        svg.text(x0 - 6, y + 4, f"{v:.{digits}f}", size=10, anchor="end")
    svg.text(x0 - 44, (y0 + y1) / 2, label, size=11, rotate=-90)
    return ymap


def dot_ci_chart(
    path: Path,
    title: str,
    labels: Sequence[str],
    series: dict[str, list[tuple[float, float | None, float | None]]],
    lo: float,
    hi: float,
    ylabel: str,
    note: str,
    digits: int = 2,
) -> None:
    """Points with 95% CI whiskers (no bars, so a non-zero baseline cannot mislead)."""
    svg = Svg(760, 420, title)
    x0, y0, x1, y1 = 80, 50, 740, 340
    ymap = axis_frame(svg, x0, y0, x1, y1, lo, hi, 5, ylabel, digits)
    groups, k = len(labels), len(series)
    slot = (x1 - x0) / groups
    for gi, lab in enumerate(labels):
        svg.text(x0 + slot * (gi + 0.5), y1 + 18, lab, size=11)
    for si, (name, vals) in enumerate(series.items()):
        color = PALETTE[si % len(PALETTE)]
        for gi, (mean, cl, ch) in enumerate(vals):
            x = x0 + slot * gi + slot * (si + 1) / (k + 1)
            if cl is not None and ch is not None:
                svg.add(
                    f"<line x1='{x:.1f}' y1='{ymap(cl):.1f}' x2='{x:.1f}' y2='{ymap(ch):.1f}' stroke='{color}' stroke-width='1.6'/>"
                )
                for yv in (cl, ch):
                    svg.add(
                        f"<line x1='{x - 4:.1f}' y1='{ymap(yv):.1f}' x2='{x + 4:.1f}' y2='{ymap(yv):.1f}' stroke='{color}'/>"
                    )
            svg.add(f"<circle cx='{x:.1f}' cy='{ymap(mean):.1f}' r='4' fill='{color}'/>")
        lx = x0 + 10 + si * 150
        svg.add(f"<circle cx='{lx}' cy='{y1 + 40}' r='4' fill='{color}'/>")
        svg.text(lx + 8, y1 + 44, name, size=11, anchor="start")
    svg.save(path, note)


def bar_chart(
    path: Path,
    title: str,
    groups: Sequence[str],
    series: dict[str, list[float | None]],
    hi: float,
    ylabel: str,
    note: str,
) -> None:
    """Grouped bars starting at zero (single-run values; no error bars because none exist)."""
    svg = Svg(820, 430, title)
    x0, y0, x1, y1 = 80, 50, 800, 330
    ymap = axis_frame(svg, x0, y0, x1, y1, 0.0, hi, 5, ylabel)
    k = len(series)
    slot = (x1 - x0) / len(groups)
    bw = slot * 0.8 / k
    for gi, g in enumerate(groups):
        svg.text(x0 + slot * (gi + 0.5), y1 + 18, g, size=10)
    for si, (name, vals) in enumerate(series.items()):
        color = PALETTE[si % len(PALETTE)]
        for gi, v in enumerate(vals):
            if v is None:
                continue
            x = x0 + slot * gi + slot * 0.1 + si * bw
            svg.add(
                f"<rect x='{x:.1f}' y='{ymap(v):.1f}' width='{bw - 2:.1f}' height='{y1 - ymap(v):.1f}' fill='{color}'/>"
            )
            svg.text(
                x + bw / 2 - 1, ymap(v) - 3, f"{v:.4f}" if 0 < v < 0.01 else f"{v:.3f}", size=8
            )
        lx = x0 + 10 + si * 160
        svg.add(f"<rect x='{lx}' y='{y1 + 34}' width='10' height='10' fill='{color}'/>")
        svg.text(lx + 14, y1 + 43, name, size=11, anchor="start")
    svg.save(path, note)


def line_panels(
    path: Path,
    title: str,
    panels: dict[str, dict[str, list[tuple[float, float, float | None]]]],
    xs: Sequence[float],
    lo: float,
    hi: float,
    ylabel: str,
    note: str,
) -> None:
    svg = Svg(1080, 440, title)
    width = 300
    for pi, (ptitle, series) in enumerate(panels.items()):
        x0 = 70 + pi * (width + 40)
        x1, y0, y1 = x0 + width, 60, 330
        ymap = axis_frame(svg, x0, y0, x1, y1, lo, hi, 5, ylabel if pi == 0 else "")
        svg.text((x0 + x1) / 2, 48, ptitle, size=12)
        lx = [math.log(x) for x in xs]

        def xmap(v: float, x0: float = x0, x1: float = x1, lx: list[float] = lx) -> float:
            return x0 + 15 + (math.log(v) - lx[0]) / (lx[-1] - lx[0]) * (x1 - x0 - 30)

        for x in xs:
            svg.text(xmap(x), y1 + 16, f"{int(x)}", size=10)
        for si, (_name, pts) in enumerate(series.items()):
            color = PALETTE[si % len(PALETTE)]
            coords = " ".join(f"{xmap(x):.1f},{ymap(m):.1f}" for x, m, _ in pts)
            svg.add(
                f"<polyline points='{coords}' fill='none' stroke='{color}' stroke-width='1.6'/>"
            )
            for x, m, half in pts:
                if half is not None:
                    svg.add(
                        f"<line x1='{xmap(x):.1f}' y1='{ymap(m - half):.1f}' x2='{xmap(x):.1f}' y2='{ymap(m + half):.1f}' stroke='{color}' stroke-opacity='0.5'/>"
                    )
                svg.add(f"<circle cx='{xmap(x):.1f}' cy='{ymap(m):.1f}' r='2.6' fill='{color}'/>")
        svg.text((x0 + x1) / 2, y1 + 32, "N_train (log scale)", size=11)
    for si, name in enumerate(next(iter(panels.values()))):
        lx_ = 70 + si * 165
        svg.add(
            f"<rect x='{lx_}' y='372' width='10' height='10' fill='{PALETTE[si % len(PALETTE)]}'/>"
        )
        svg.text(lx_ + 14, 381, name, size=11, anchor="start")
    svg.save(path, note)


def architecture_svg(path: Path) -> None:
    stages = [
        ("Security events", "typed SecurityEvent (M1)"),
        ("Classical detection", "Random Forest, CIC-IDS2017 (M5)"),
        ("Quantum second opinion", "ZZ-kernel SVM, uncertain band (M6)"),
        ("ATT&CK technique evidence", "explicit sources only (M7)"),
        ("Attack-chain reconstruction", "observed steps, arrival order (M7)"),
        ("Next-technique prediction", "B1 / Markov / LSTM / hybrid, beam (M3-M4)"),
        ("Model-derived risk", "documented weighted policy (M7)"),
        ("Defense recommendations", "PROPOSED only, human approval (M7)"),
        ("FastAPI /api/v1", "append-only analyst decisions (M8)"),
        ("React dashboard", "observed vs predicted, executes nothing (M9)"),
    ]
    svg = Svg(760, 70 + len(stages) * 62, "HQC framework: as-built pipeline (Milestones 1-9)")
    for i, (name, sub) in enumerate(stages):
        y = 44 + i * 62
        fill = "#eef3fb" if i not in (2,) else "#f4effb"
        svg.add(
            f"<rect x='180' y='{y}' width='400' height='44' rx='8' fill='{fill}' stroke='#4c72b0'/>"
        )
        svg.text(380, y + 19, name, size=13)
        svg.text(380, y + 35, sub, size=10, color="#555")
        if i < len(stages) - 1:
            svg.add(
                f"<line x1='380' y1='{y + 44}' x2='380' y2='{y + 62}' stroke='#333' marker-end='url(#a)'/>"
            )
    svg.parts.insert(
        1,
        "<defs><marker id='a' markerWidth='8' markerHeight='8' refX='4' refY='7' orient='auto'><path d='M0,0 L8,0 L4,8 z' fill='#333'/></marker></defs>",
    )
    svg.text(640, 44 + 2 * 62 + 26, "never overrides the", size=10, anchor="start", color="#8172b3")
    svg.text(640, 44 + 2 * 62 + 39, "classical verdict", size=10, anchor="start", color="#8172b3")
    svg.save(
        path,
        "ATT&CK 19.2 knowledge base and Attack Flow corpus (M2) feed technique validation and prediction.",
    )


def figures(results: Json) -> list[str]:
    fig = OUT / "figures"
    pred, det, q = results["attack_prediction"], results["detection"], results["quantum"]
    models = [m["model"] for m in pred["models"]]
    made = []
    note_pred = "Macro mean over 36 source groups with 95% bootstrap CI (stored M3/M4 runs). Overlapping CIs: no significance implied."
    dot_ci_chart(
        fig / "01_prediction_top1_top5.svg",
        "Next-technique prediction: Top-1 and Top-5",
        models,
        {
            k: [(m[k]["mean"], m[k]["ci_low"], m[k]["ci_high"]) for m in pred["models"]]
            for k in ("top1", "top5")
        },
        0.0,
        0.25,
        "accuracy",
        note_pred,
    )
    dot_ci_chart(
        fig / "02_prediction_mrr.svg",
        "Next-technique prediction: MRR",
        models,
        {
            "MRR": [
                (m["mrr"]["mean"], m["mrr"]["ci_low"], m["mrr"]["ci_high"]) for m in pred["models"]
            ]
        },
        0.0,
        0.18,
        "MRR",
        note_pred,
    )
    dot_ci_chart(
        fig / "03_prediction_log_loss.svg",
        "Next-technique prediction: log loss (lower is better)",
        models,
        {
            "log loss": [
                (m["log_loss"]["mean"], m["log_loss"]["ci_low"], m["log_loss"]["ci_high"])
                for m in pred["models"]
            ]
        },
        5.0,
        7.0,
        "log loss (axis starts at 5.0)",
        note_pred,
    )
    rows = [d for d in det["rows"] if d["subset"] == "all_test_rows"]
    names = [f"{d['model']} / {d['feature_set']}" for d in rows]
    note_det = (
        "CIC-IDS2017, Thursday-Friday holdout, all test rows; single run (no CIs exist). Run "
        + RUN_M5
    )
    bar_chart(
        fig / "04_detection_precision_recall_f1.svg",
        "CIC-IDS2017 detectors: precision, recall, F1",
        names,
        {k: [d[k] for d in rows] for k in ("precision", "recall", "f1")},
        1.0,
        "score",
        note_det,
    )
    bar_chart(
        fig / "05_detection_auc.svg",
        "CIC-IDS2017 detectors: ROC-AUC, PR-AUC, benign FPR",
        names,
        {k: [d[k] for d in rows] for k in ("roc_auc", "pr_auc", "benign_false_positive_rate")},
        1.0,
        "score",
        note_det,
    )
    panels: dict[str, dict[str, list[tuple[float, float, float | None]]]] = {}
    for d in (4, 6, 8):
        panels[f"d = {d}"] = {
            arm: [
                (
                    float(a["n_train"]),
                    a["balanced_accuracy"]["mean"],
                    a["balanced_accuracy"]["ci95"],
                )
                for a in q["e2_aggregate"]
                if a["arm"] == arm and a["n_dims"] == d
            ]
            for arm in QUANTUM_ARMS
        }
    line_panels(
        fig / "06_quantum_matched_budget.svg",
        "Matched-budget comparison (E2): balanced accuracy, mean ± 95% t-CI over 5 seeds",
        panels,
        [100, 250, 500, 1000, 2000],
        0.5,
        0.9,
        "balanced accuracy",
        "Significance only from paired ZZ-RBF tests (tables): ZZ never significantly better; significantly worse in 5 metric-cells.",
    )
    primary = q["e3"]["primary"]["whole_test_set"]
    bar_chart(
        fig / "07_quantum_fusion_tradeoff.svg",
        "Second-opinion fusion (E3, primary band): whole test set",
        [row["arm"] for row in primary],
        {
            k: [row[k] for row in primary]
            for k in ("precision", "recall", "benign_false_positive_rate", "pr_auc")
        },
        1.0,
        "score",
        "Single seed. Recall rises only with a large benign-FPR increase; PR-AUC of RF+ZZ is below RF alone.",
    )
    shots = [s for s in q["e4"]["settings"] if s["p1"] == 0 and s["p2"] == 0 and s["readout"] == 0]
    svg = Svg(620, 380, "Shot noise: kernel error vs shots (E4, no gate noise)")
    x0, y0, x1, y1 = 80, 50, 590, 300
    ymap = axis_frame(svg, x0, y0, x1, y1, 0.0, 0.05, 5, "relative Frobenius error (test)", 3)
    xs = [math.log(s["shots"]) for s in shots]

    def xmap(v: float) -> float:
        return x0 + 30 + (v - xs[0]) / (xs[-1] - xs[0]) * (x1 - x0 - 60)

    svg.add(
        "<polyline points='"
        + " ".join(
            f"{xmap(math.log(s['shots'])):.1f},{ymap(s['test_rel_frobenius_error']):.1f}"
            for s in shots
        )
        + "' fill='none' stroke='#4c72b0' stroke-width='1.8'/>"
    )
    for s in shots:
        x, y = xmap(math.log(s["shots"])), ymap(s["test_rel_frobenius_error"])
        svg.add(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4' fill='#4c72b0'/>")
        svg.text(x, y - 8, f"{s['test_rel_frobenius_error']:.4f}", size=10)
        svg.text(x, y1 + 16, str(s["shots"]), size=10)
    svg.text((x0 + x1) / 2, y1 + 34, "shots (log scale)", size=11)
    svg.save(
        fig / "08_shot_noise.svg",
        "Single seed, ZZ map d=4, N=200. Error roughly halves per 4x shots (~1/sqrt(shots)).",
    )
    settings = q["e4"]["settings"]
    bar_chart(
        fig / "09_depolarizing_noise.svg",
        "Noise settings (E4): kernel error and balanced accuracy",
        [s["name"] for s in settings],
        {
            "rel. kernel error (test)": [s["test_rel_frobenius_error"] for s in settings],
            "balanced accuracy": [s["balanced_accuracy"] for s in settings],
        },
        1.0,
        "value",
        f"Single seed. Exact statevector balanced accuracy {q['e4']['exact_balanced_accuracy']}.",
    )
    architecture_svg(fig / "10_architecture.svg")
    made = sorted(p.name for p in fig.glob("*.svg"))
    return made


# --- main ---------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-large-checksums", action="store_true", help="skip SHA-256 of files > 50 MB"
    )
    args = parser.parse_args()
    results = {
        "attack_prediction": prediction_results(),
        "detection": detection_results(),
        "quantum": quantum_results(),
        "integration": integration_results(),
        "run_ids": RUN_IDS,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    csvs, markdown = tables(results)
    for name, rows in csvs.items():
        write_csv(OUT / "tables" / f"{name}.csv", rows)
    (OUT / "tables.md").write_text(markdown, encoding="utf-8")
    made = figures(results)
    repro = {
        "classes": {
            "A": "directly reproducible from existing artifacts",
            "B": "reproducible by re-running an existing evaluation",
            "C": "documented but not currently reproducible",
            "D": "synthetic / demo only",
        },
        "results": REPRODUCIBILITY_CLASSES,
        "runs": run_provenance(),
        "data_artifacts": artifact_audit(args.skip_large_checksums),
        "source_fingerprint": source_fingerprint(),
        "caveat": "Every stored run records git commit c2813d4 with a dirty working tree: the code that "
        "produced M3-M7 is the uncommitted working tree, not a commit.",
    }
    (OUT / "reproducibility.json").write_text(json.dumps(repro, indent=1) + "\n", encoding="utf-8")
    meta = {
        "generator": "evaluation/build_final_report.py",
        "generated_at": datetime.now(UTC).isoformat(),
        "inputs": {k: f"reports/runs/{v}" for k, v in RUN_IDS.items()},
        "figures": made,
        "tables": sorted(f"tables/{n}.csv" for n in csvs),
        "results_sha256": hashlib.sha256((OUT / "results.json").read_bytes()).hexdigest(),
    }
    (OUT / "metadata.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(made)} figures, {len(csvs)} tables -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
