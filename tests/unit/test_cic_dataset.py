"""CIC-IDS2017 CSV adapter (synthetic fixtures; the real dataset is not needed)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from cic_fixtures import RAW_HEADER, write_day_files
from hqc.common.errors import DatasetNotFoundError, FeatureSchemaMismatchError
from hqc.detection.dataset import (
    EXPECTED_COLUMNS,
    day_of,
    discover_csv_files,
    load_cic_dataset,
    normalize_column_name,
    normalize_header,
    normalize_label,
    read_cic_csv,
)


def test_column_name_normalisation() -> None:
    assert normalize_column_name(" Flow Bytes/s") == "flow_bytes_s"
    assert normalize_column_name("Init_Win_bytes_forward") == "init_win_bytes_forward"
    assert normalize_column_name(" Down/Up Ratio ") == "down_up_ratio"
    header = normalize_header(RAW_HEADER)
    assert header == list(EXPECTED_COLUMNS)
    assert header.count("fwd_header_length") == 1 and "fwd_header_length__dup1" in header


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("BENIGN", "BENIGN"),
        ("  DoS  Hulk ", "DoS Hulk"),
        ("Web Attack � Brute Force", "Web Attack - Brute Force"),
        ("Web Attack \u2013 XSS", "Web Attack - XSS"),
    ],
)
def test_label_normalisation(raw: str, expected: str) -> None:
    assert normalize_label(raw) == expected


def test_day_detection_and_discovery_order(tmp_path: Path) -> None:
    directory = write_day_files(tmp_path / "cic")
    (directory / "nested").mkdir()
    nested = directory / "nested" / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
    nested.write_text(",".join(RAW_HEADER) + "\n")
    names = [p.name for p in discover_csv_files(directory)]
    assert names == [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    ]
    assert day_of(Path("Wednesday-workingHours.pcap_ISCX.csv")) == "Wednesday"
    with pytest.raises(FeatureSchemaMismatchError):
        day_of(Path("Saturday.csv"))
    with pytest.raises(DatasetNotFoundError):
        discover_csv_files(tmp_path / "absent")
    (tmp_path / "empty").mkdir()
    with pytest.raises(DatasetNotFoundError):
        discover_csv_files(tmp_path / "empty")


def test_messy_file_is_read_with_counts(tmp_path: Path) -> None:
    directory = write_day_files(tmp_path / "cic", rows_per_label=5)
    thursday = read_cic_csv(directory / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
    r = thursday.report
    assert r.encoding == "cp1252"
    assert r.rows_read == 10 + 4
    assert r.empty_rows_dropped == 1 and r.missing_label_rows_dropped == 1
    assert r.rows_kept == 12
    assert r.malformed_numeric_cells == {"flow_iat_mean": 1}
    assert r.infinite_cells == {"flow_bytes_s": 1}
    assert r.nan_cells["flow_packets_s"] == 1 and r.nan_cells["flow_iat_mean"] == 1
    assert len(r.sha256) == 64 and r.day == "Thursday"
    frame = thursday.frame
    assert np.isinf(frame["flow_bytes_s"]).sum() == 1
    assert set(frame["label"]) == {"BENIGN", "Web Attack - XSS"}
    assert "Web Attack \u2013 XSS" in set(frame["raw_label"])  # original label preserved
    assert frame["is_malicious"].sum() == 5
    assert frame["row_number"].tolist() == list(range(12))
    assert frame["source_ip"].iloc[0].startswith("192.168.10.")
    assert set(frame["protocol"]) == {6.0, 17.0}


def test_unexpected_or_missing_columns_raise(tmp_path: Path) -> None:
    extra = tmp_path / "Monday-x.csv"
    extra.write_text(",".join([*RAW_HEADER, "Surprise"]) + "\n")
    with pytest.raises(FeatureSchemaMismatchError, match="surprise"):
        read_cic_csv(extra)
    missing = tmp_path / "Tuesday-x.csv"
    missing.write_text(",".join(RAW_HEADER[:-1]) + "\n")
    with pytest.raises(FeatureSchemaMismatchError, match="label"):
        read_cic_csv(missing)


def test_load_dataset_statistics(tmp_path: Path) -> None:
    ds = load_cic_dataset(write_day_files(tmp_path / "cic", rows_per_label=6))
    s = ds.stats
    assert len(s.files) == 5
    assert s.rows_total == len(ds.frame) == sum(f.rows_kept for f in s.files)
    assert s.rows_per_day == {
        "Monday": 6,
        "Tuesday": 12,
        "Wednesday": 12,
        "Thursday": 14,
        "Friday": 12,
    }
    assert s.label_counts["DDoS"] == 6 and s.label_counts["BENIGN"] == 6 * 5 + 2
    assert 0 < s.malicious_fraction < 1
