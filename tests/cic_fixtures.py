"""Tiny SYNTHETIC CIC-IDS2017-format CSVs for tests (not real traffic).

Uses the real GeneratedLabelledFlows header (leading spaces, duplicated
"Fwd Header Length") so the adapter is exercised exactly as on the real files.
"""

from __future__ import annotations

import random
from pathlib import Path

from hqc.detection.dataset import NUMERIC_FLOW_COLUMNS

RAW_HEADER: list[str] = [
    "Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port",
    " Protocol", " Timestamp", " Flow Duration", " Total Fwd Packets",
    " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    " Fwd Packet Length Max", " Fwd Packet Length Min", " Fwd Packet Length Mean",
    " Fwd Packet Length Std", "Bwd Packet Length Max", " Bwd Packet Length Min",
    " Bwd Packet Length Mean", " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s",
    " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total",
    " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total",
    " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags",
    " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length",
    " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length",
    " Max Packet Length", " Packet Length Mean", " Packet Length Std",
    " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count",
    " PSH Flag Count", " ACK Flag Count", " URG Flag Count", " CWE Flag Count",
    " ECE Flag Count", " Down/Up Ratio", " Average Packet Size", " Avg Fwd Segment Size",
    " Avg Bwd Segment Size", " Fwd Header Length", "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes",
    "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd",
    " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min",
    "Idle Mean", " Idle Std", " Idle Max", " Idle Min", " Label",
]  # fmt: skip

DAY_FILES: dict[str, list[str]] = {
    "Monday-WorkingHours.pcap_ISCX.csv": ["BENIGN"],
    "Tuesday-WorkingHours.pcap_ISCX.csv": ["BENIGN", "FTP-Patator"],
    "Wednesday-workingHours.pcap_ISCX.csv": ["BENIGN", "DoS Hulk"],
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": ["BENIGN", "Web Attack � XSS"],
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": ["BENIGN", "DDoS"],
}


def flow_row(rng: random.Random, label: str, index: int, protocol: int = 6) -> list[str]:
    malicious = label != "BENIGN"
    values: dict[str, str] = {}
    for column in NUMERIC_FLOW_COLUMNS:
        if column in ("bwd_psh_flags", "fwd_avg_bytes_bulk"):
            values[column] = "0"  # constant columns, as in the real data
            continue
        base = 1000.0 if malicious else 10.0
        values[column] = f"{base * (1 + rng.random()):.3f}"
    values["fwd_header_length__dup1"] = values["fwd_header_length"]
    src = f"192.168.10.{index % 50}"
    meta = [
        f"{src}-172.16.0.1-{40000 + index}-80-{protocol}",
        src,
        str(40000 + index),
        "172.16.0.1",
        "80" if malicious else str(443 + index % 3),
        str(protocol),
        f"3/7/2017 9:{index % 60:02d}",
    ]
    return meta + [values[c] for c in NUMERIC_FLOW_COLUMNS] + [label]


def write_day_files(
    directory: Path, rows_per_label: int = 12, seed: int = 0, extras: bool = True
) -> Path:
    """Write the five synthetic day files. ``extras`` adds messy rows to Thursday."""
    rng = random.Random(seed)
    directory.mkdir(parents=True, exist_ok=True)
    for name, labels in DAY_FILES.items():
        lines = [",".join(RAW_HEADER)]
        index = 0
        for label in labels:
            for _ in range(rows_per_label):
                lines.append(",".join(flow_row(rng, label, index)))
                index += 1
        if extras and name.startswith("Thursday"):
            row = flow_row(rng, "BENIGN", index)
            row[RAW_HEADER.index("Flow Bytes/s")] = "Infinity"
            row[RAW_HEADER.index(" Flow Packets/s")] = "NaN"
            row[RAW_HEADER.index(" Flow IAT Mean")] = "abc"  # malformed numeric cell
            lines.append(",".join(row))
            lines.append("," * (len(RAW_HEADER) - 1))  # fully empty row
            no_label = flow_row(rng, "BENIGN", index + 1)
            no_label[-1] = ""
            lines.append(",".join(no_label))
            lines.append(",".join(flow_row(rng, "BENIGN", index + 2, protocol=17)))
        encoding = "cp1252" if name.startswith("Thursday") else "utf-8"
        text = "\n".join(lines) + "\n"
        if encoding == "cp1252":
            text = text.replace("�", "\u2013")  # en dash, encoded as byte 0x96
        (directory / name).write_bytes(text.encode(encoding))
    return directory
