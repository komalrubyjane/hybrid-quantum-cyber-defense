"""CIC-IDS2017 (GeneratedLabelledFlows / "TrafficLabelling") CSV adapter.

Reads the per-day CICFlowMeter CSVs into one normalised pandas frame:

- files are discovered recursively and ordered deterministically (weekday, then name);
- column names are normalised (``" Flow Bytes/s"`` -> ``flow_bytes_s``); the header must
  match the expected CIC-IDS2017 schema exactly: unexpected or missing columns raise
  :class:`FeatureSchemaMismatchError` (nothing is dropped silently);
- the duplicated ``Fwd Header Length`` column is kept as ``fwd_header_length__dup1`` and
  handled by the feature policy;
- fully empty rows and rows without a label are dropped and COUNTED;
- numeric cells that cannot be parsed become NaN and are COUNTED as malformed;
  NaN and +/-inf are counted per column (imputation happens later, train-only);
- the original label string is preserved (``raw_label``); ``label`` is a normalised form
  (whitespace, replacement characters) and ``is_malicious`` = label != BENIGN.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from hqc.common.errors import DatasetNotFoundError, FeatureSchemaMismatchError
from hqc.common.provenance import sha256_bytes
from hqc.detection.schemas import DatasetStats, FileReport

DAY_ORDER: tuple[str, ...] = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
BENIGN_LABEL = "BENIGN"
ENCODINGS: tuple[str, ...] = ("utf-8", "cp1252", "latin-1")

# Header of the GeneratedLabelledFlows CSVs (CICFlowMeter), normalised. "Fwd Header Length"
# appears twice in the original header; the second occurrence becomes "__dup1".
METADATA_COLUMNS: tuple[str, ...] = (
    "flow_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "timestamp",
)
NUMERIC_FLOW_COLUMNS: tuple[str, ...] = (
    "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean",
    "fwd_packet_length_std", "bwd_packet_length_max", "bwd_packet_length_min",
    "bwd_packet_length_mean", "bwd_packet_length_std", "flow_bytes_s", "flow_packets_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_total",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "bwd_iat_total",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min", "fwd_psh_flags",
    "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "fwd_header_length",
    "bwd_header_length", "fwd_packets_s", "bwd_packets_s", "min_packet_length",
    "max_packet_length", "packet_length_mean", "packet_length_std",
    "packet_length_variance", "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count", "cwe_flag_count",
    "ece_flag_count", "down_up_ratio", "average_packet_size", "avg_fwd_segment_size",
    "avg_bwd_segment_size", "fwd_header_length__dup1", "fwd_avg_bytes_bulk",
    "fwd_avg_packets_bulk", "fwd_avg_bulk_rate", "bwd_avg_bytes_bulk",
    "bwd_avg_packets_bulk", "bwd_avg_bulk_rate", "subflow_fwd_packets",
    "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_forward", "init_win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
)  # fmt: skip
LABEL_COLUMN = "label"
EXPECTED_COLUMNS: tuple[str, ...] = (*METADATA_COLUMNS, *NUMERIC_FLOW_COLUMNS, LABEL_COLUMN)
NUMERIC_METADATA = ("source_port", "destination_port", "protocol")

REPLACEMENT_CHAR = chr(0xFFFD)  # mojibake from mis-decoded labels
EN_DASH = chr(0x2013)
EM_DASH = chr(0x2014)

_DAY_RE = re.compile(r"(Monday|Tuesday|Wednesday|Thursday|Friday)", re.IGNORECASE)


def normalize_column_name(name: str) -> str:
    """``" Flow Bytes/s"`` -> ``flow_bytes_s``; ``"Init_Win_bytes_forward"`` -> lower snake."""
    cleaned = re.sub(r"[^0-9a-zA-Z]+", "_", name.strip()).strip("_").lower()
    return re.sub(r"_+", "_", cleaned)


def normalize_header(raw: list[str]) -> list[str]:
    """Normalise names and disambiguate repeats as ``name__dupN`` (order preserved)."""
    seen: dict[str, int] = {}
    out = []
    for column in raw:
        name = normalize_column_name(column)
        count = seen.get(name, 0)
        seen[name] = count + 1
        out.append(name if count == 0 else f"{name}__dup{count}")
    return out


def normalize_label(raw: str) -> str:
    """Trim, replace mojibake / dash variants by ``-`` and collapse whitespace."""
    text = raw.replace(REPLACEMENT_CHAR, "-").replace(EN_DASH, "-").replace(EM_DASH, "-")
    text = text.replace("\x96", "-")
    return re.sub(r"\s+", " ", text).strip()


def day_of(path: Path) -> str:
    match = _DAY_RE.search(path.name)
    if match is None:
        raise FeatureSchemaMismatchError(f"Cannot determine the weekday of {path.name}")
    return match.group(1).capitalize()


def discover_csv_files(directory: Path) -> list[Path]:
    """All ``*.csv`` files below ``directory`` ordered by weekday then file name."""
    if not directory.is_dir():
        raise DatasetNotFoundError(f"CIC-IDS2017 directory not found: {directory}")
    files = [p for p in directory.rglob("*.csv") if p.is_file()]
    if not files:
        raise DatasetNotFoundError(f"No CSV files under {directory}")
    return sorted(files, key=lambda p: (DAY_ORDER.index(day_of(p)), p.name))


def _decode(data: bytes) -> tuple[str, str]:
    for encoding in ENCODINGS:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise FeatureSchemaMismatchError("Undecodable CSV")  # latin-1 never fails


@dataclass
class CicFile:
    frame: pd.DataFrame
    report: FileReport


STRING_COLUMNS: tuple[str, ...] = (
    "flow_id",
    "source_ip",
    "destination_ip",
    "timestamp",
    LABEL_COLUMN,
)
NA_TOKENS: tuple[str, ...] = ("", "NaN", "nan", "NA")


def read_cic_csv(path: Path) -> CicFile:
    """Read and normalise one CIC-IDS2017 CSV (see module docstring).

    Numbers are parsed by pandas' C parser ("Infinity" -> inf). Columns that contain
    unparsable text are coerced cell by cell and the failures counted as malformed.
    """
    data = path.read_bytes()
    text, encoding = _decode(data)
    first_line = next(csv.reader(io.StringIO(text.split("\n", 1)[0])))
    header = normalize_header(first_line)
    unexpected = [c for c in header if c not in EXPECTED_COLUMNS]
    missing = [c for c in EXPECTED_COLUMNS if c not in header]
    if unexpected or missing:
        raise FeatureSchemaMismatchError(
            f"{path.name}: unexpected columns {unexpected}; missing columns {missing}"
        )
    raw = pd.read_csv(
        io.StringIO(text),
        header=0,
        names=header,
        dtype={c: str for c in STRING_COLUMNS},
        na_values=list(NA_TOKENS),
        keep_default_na=False,
        low_memory=False,
    )
    del text
    rows_read = len(raw)
    empty = raw.isna().all(axis=1)
    no_label = ~empty & raw[LABEL_COLUMN].fillna("").str.strip().eq("")
    raw = raw.loc[~empty & ~no_label].reset_index(drop=True)

    frame = pd.DataFrame(index=raw.index)
    for column in ("flow_id", "source_ip", "destination_ip", "timestamp"):
        frame[column] = raw[column].fillna("").str.strip()
    malformed: dict[str, int] = {}
    nan_cells: dict[str, int] = {}
    inf_cells: dict[str, int] = {}
    for column in (*NUMERIC_METADATA, *NUMERIC_FLOW_COLUMNS):
        original = raw[column]
        if not pd.api.types.is_numeric_dtype(original):
            values = pd.to_numeric(original.str.strip(), errors="coerce")
            bad = int((original.notna() & values.isna()).sum())
            if bad:
                malformed[column] = bad
        else:
            values = original.astype(np.float64)
        as_float = values.to_numpy(dtype=np.float64)
        n_nan = int(np.isnan(as_float).sum())
        n_inf = int(np.isinf(as_float).sum())
        if n_nan:
            nan_cells[column] = n_nan
        if n_inf:
            inf_cells[column] = n_inf
        frame[column] = as_float.astype(np.float64 if column in NUMERIC_METADATA else np.float32)
    frame["raw_label"] = raw[LABEL_COLUMN]
    frame["label"] = raw[LABEL_COLUMN].map(normalize_label)
    frame["is_malicious"] = (frame["label"] != BENIGN_LABEL).astype(np.int8)
    day = day_of(path)
    frame["day"] = day
    frame["source_file"] = path.name
    frame["row_number"] = np.arange(len(frame), dtype=np.int64)
    counts = frame["raw_label"].value_counts().sort_index()
    report = FileReport(
        file_name=path.name,
        sha256=sha256_bytes(data),
        size_bytes=len(data),
        day=day,
        encoding=encoding,
        rows_read=rows_read,
        empty_rows_dropped=int(empty.sum()),
        missing_label_rows_dropped=int(no_label.sum()),
        rows_kept=len(frame),
        malformed_numeric_cells=malformed,
        nan_cells=nan_cells,
        infinite_cells=inf_cells,
        raw_label_counts={str(k): int(v) for k, v in counts.items()},
    )
    return CicFile(frame, report)


@dataclass
class CicDataset:
    frame: pd.DataFrame
    stats: DatasetStats


def load_cic_dataset(directory: Path) -> CicDataset:
    """Load every CSV below ``directory`` (deterministic order) into one frame."""
    parts = [read_cic_csv(p) for p in discover_csv_files(directory)]
    frame = pd.concat([p.frame for p in parts], ignore_index=True)
    label_counts = frame["label"].value_counts().sort_index()
    stats = DatasetStats(
        files=[p.report for p in parts],
        rows_total=len(frame),
        rows_per_day={
            d: int((frame["day"] == d).sum()) for d in DAY_ORDER if (frame["day"] == d).any()
        },
        label_counts={str(k): int(v) for k, v in label_counts.items()},
        malicious_fraction=float(frame["is_malicious"].mean()) if len(frame) else 0.0,
    )
    return CicDataset(frame, stats)
