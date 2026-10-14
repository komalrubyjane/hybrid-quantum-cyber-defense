"""Day split, feature policy, train-only preprocessing, duplicates, models, metrics,
experiment tracking and dataset registration (synthetic data only)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest

from cic_fixtures import write_day_files
from hqc.common.errors import (
    ConfigurationError,
    DataLeakageError,
    DatasetNotFoundError,
    FeatureSchemaMismatchError,
    MalformedSourceDataError,
    ModelCheckpointNotFoundError,
    StorageError,
)
from hqc.common.repro import environment_info
from hqc.common.schemas import DetectionResult, EvaluationResult, Verdict
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT
from hqc.detection.dataset import CicDataset, load_cic_dataset
from hqc.detection.evaluation import binary_metrics, evaluate_block
from hqc.detection.experiment import (
    ALL_TEST,
    FULL,
    NO_CROSS_DUP,
    NO_DSTPORT,
    DetectionConfig,
    load_detection_config,
    run_detection_experiment,
)
from hqc.detection.models import Detector, ModelConfig, train_detector
from hqc.detection.preprocessing import (
    IDENTIFIER_FEATURES,
    LEAKAGE_FEATURES,
    Preprocessor,
    build_feature_policy,
    day_split,
    duplicate_audit,
    feature_row_hashes,
    split_masks,
)
from hqc.detection.registration import extract_csvs, manifest_entries, safe_member_path
from hqc.detection.tracking import (
    RUN_FILES,
    DetectionProvenance,
    detection_record,
    make_detection_run_id,
    store_detection_record,
    write_detection_run,
)
from hqc.storage import SQLiteStore

TRAIN_DAYS = ["Monday", "Tuesday", "Wednesday"]
TEST_DAYS = ["Thursday", "Friday"]
Frames = tuple[pd.DataFrame, pd.DataFrame]


@pytest.fixture(scope="module")
def dataset(tmp_path_factory: pytest.TempPathFactory) -> CicDataset:
    return load_cic_dataset(write_day_files(tmp_path_factory.mktemp("cic"), rows_per_label=15))


@pytest.fixture(scope="module")
def frames(dataset: CicDataset) -> Frames:
    split = day_split(dataset.frame, TRAIN_DAYS, TEST_DAYS)
    tr, te = split_masks(dataset.frame, split)
    return (
        dataset.frame.loc[tr].reset_index(drop=True),
        dataset.frame.loc[te].reset_index(drop=True),
    )


def config(**overrides: Any) -> DetectionConfig:
    data: dict[str, Any] = {
        "seed": 3,
        "dataset_dir": "unused",
        "threshold": 0.5,
        "train_days": TRAIN_DAYS,
        "test_days": TEST_DAYS,
        "models": [
            {"name": "logreg", "seed": 3, "logreg_max_iter": 200},
            {"name": "random_forest", "seed": 3, "rf_n_estimators": 10, "n_jobs": 1},
        ],
    }
    data.update(overrides)
    return DetectionConfig.model_validate(data)


# --- split ------------------------------------------------------------------------------------


def test_whole_day_split(dataset: CicDataset, frames: Frames) -> None:
    split = day_split(dataset.frame, TRAIN_DAYS, TEST_DAYS)
    assert split.train_files == (
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
    )
    assert set(split.test_files) == {
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    }
    train, test = frames
    assert set(train["day"]) == set(TRAIN_DAYS) and set(test["day"]) == set(TEST_DAYS)
    assert not set(train["source_file"]) & set(test["source_file"])
    with pytest.raises(DataLeakageError):
        day_split(dataset.frame, ["Monday", "Thursday"], ["Thursday", "Friday"])
    with pytest.raises(FeatureSchemaMismatchError, match="not assigned"):
        day_split(dataset.frame, ["Monday"], ["Friday"])
    with pytest.raises(FeatureSchemaMismatchError, match="no data"):
        day_split(dataset.frame, [*TRAIN_DAYS, "Saturday"], TEST_DAYS)


# --- feature policy ---------------------------------------------------------------------------


def test_feature_policy(frames: Frames) -> None:
    train, _ = frames
    policy = build_feature_policy(train)
    used = set(policy.used_features)
    assert not used & set(IDENTIFIER_FEATURES) and not used & set(LEAKAGE_FEATURES)
    assert "destination_port" in used and "destination_port" in policy.shortcut_risk_features
    assert "fwd_header_length__dup1" in policy.dropped_duplicate_columns
    assert {"bwd_psh_flags", "fwd_avg_bytes_bulk"} <= set(policy.dropped_constant_features)
    assert policy.categorical_features == {"protocol": ["6"]}  # training protocols only
    ablation = build_feature_policy(train, drop_destination_port=True)
    assert "destination_port" not in ablation.used_features
    assert ablation.version.endswith("no-dstport") and not ablation.shortcut_risk_features
    assert policy.used_features == build_feature_policy(train.iloc[::-1]).used_features


def test_non_identical_duplicate_column_is_kept(frames: Frames) -> None:
    train = frames[0].copy()
    train.loc[0, "fwd_header_length__dup1"] = -1.0
    assert "fwd_header_length__dup1" not in build_feature_policy(train).dropped_duplicate_columns


# --- preprocessing ----------------------------------------------------------------------------


def test_preprocessor_is_fitted_on_training_only(frames: Frames) -> None:
    """Regression: test data cannot influence preprocessing parameters."""
    train, test = frames
    policy = build_feature_policy(train)
    reference = Preprocessor(policy).fit(train)
    poisoned = test.copy()
    poisoned[policy.used_features] = 1e12
    again = Preprocessor(policy).fit(train)
    again.transform(poisoned)
    assert again.to_dict() == reference.to_dict() and again.version == reference.version
    combined = Preprocessor(policy).fit(pd.concat([train, test]))
    assert combined.version != reference.version  # fitting on test WOULD change parameters
    x = reference.transform(test)
    assert x.shape == (len(test), len(reference.feature_names)) and np.isfinite(x).all()


def test_preprocessor_handles_inf_nan_and_unseen_protocol(frames: Frames) -> None:
    train, test = frames
    pre = Preprocessor(build_feature_policy(train)).fit(train)
    x = pre.transform(test)
    udp = test["protocol"].to_numpy() == 17.0
    assert udp.any() and (x[udp, -1] == 0).all()  # protocol 17 unseen in training
    with pytest.raises(RuntimeError):
        Preprocessor(pre.policy).transform(test)
    with pytest.raises(FeatureSchemaMismatchError):
        pre.transform(test.drop(columns=["flow_duration"]))


def test_preprocessor_save_load_and_integrity(tmp_path: Path, frames: Frames) -> None:
    train, test = frames
    pre = Preprocessor(build_feature_policy(train)).fit(train)
    path = tmp_path / "prep.json"
    pre.save(path)
    loaded = Preprocessor.load(path)
    assert loaded.version == pre.version
    assert np.array_equal(loaded.transform(test), pre.transform(test))
    payload = json.loads(path.read_text())
    payload["means"][0] += 1.0
    path.write_text(json.dumps(payload))
    with pytest.raises(FeatureSchemaMismatchError, match="integrity"):
        Preprocessor.load(path)
    payload["format"] = "99"
    path.write_text(json.dumps(payload))
    with pytest.raises(FeatureSchemaMismatchError):
        Preprocessor.load(path)


# --- duplicates -------------------------------------------------------------------------------


def test_duplicate_audit(frames: Frames) -> None:
    train, test = frames
    policy = build_feature_policy(train)
    cols = [*policy.used_features, "protocol"]
    test = test.copy()
    test.loc[0, cols] = train.loc[0, cols].to_numpy()
    test.loc[0, "is_malicious"] = 1 - int(train.loc[0, "is_malicious"])  # conflicting label
    train2 = pd.concat([train, train.iloc[[1]]], ignore_index=True)
    audit = duplicate_audit(train2, test, policy)
    assert audit.duplicate_rows_within_train == 1
    assert audit.test_rows_with_feature_vector_in_train == 1 and audit.cross_split_mask[0]
    assert audit.cross_split_rows_with_conflicting_label == 1
    assert audit.summary()["test_rows"] == len(test)
    h = feature_row_hashes(train, policy)
    assert h.dtype == np.uint64 and len(h) == len(train)


# --- models and metrics -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def trained(frames: Frames) -> dict[str, Detector]:
    train, _ = frames
    pre = Preprocessor(build_feature_policy(train)).fit(train)
    return {m.name: train_detector(m, pre, train, "test-v1", TRAIN_DAYS) for m in config().models}


def test_models_probabilities_and_determinism(trained: dict[str, Detector], frames: Frames) -> None:
    train, test = frames
    for name, detector in trained.items():
        p = detector.predict_proba(test)
        assert p.shape == (len(test),) and ((p >= 0) & (p <= 1)).all()
        again = train_detector(
            detector.metadata.config, detector.preprocessor, train, "test-v1", TRAIN_DAYS
        )
        assert np.array_equal(again.predict_proba(test), p), name
        assert detector.metadata.model_version == again.metadata.model_version
    assert trained["random_forest"].metadata.primary_detector
    assert not trained["logreg"].metadata.primary_detector


def test_detection_results_schema(trained: dict[str, Detector], frames: Frames) -> None:
    _, test = frames
    rf = trained["random_forest"]
    results = rf.to_results(test.head(3))
    assert all(isinstance(r, DetectionResult) for r in results)
    r = results[0]
    assert r.dataset_label is None  # never attached outside offline evaluation
    assert r.verdict == (Verdict.MALICIOUS if r.p_malicious >= 0.5 else Verdict.BENIGN)
    assert r.uncertainty == pytest.approx(1 - r.confidence) and r.threshold == 0.5
    assert r.flow_id and r.feature_version and r.preprocessing_version and "day" in r.evidence
    offline = rf.to_results(test.head(1), include_dataset_label=True)[0]
    assert offline.dataset_label == test["label"].iloc[0]
    assert r.quantum is None  # slot reserved for the Milestone 6 second opinion


def test_detector_save_load(tmp_path: Path, trained: dict[str, Detector], frames: Frames) -> None:
    _, test = frames
    rf = trained["random_forest"]
    rf.save(tmp_path)
    loaded = Detector.load(tmp_path, "random_forest")
    assert np.array_equal(loaded.predict_proba(test), rf.predict_proba(test))
    assert loaded.metadata == rf.metadata
    with pytest.raises(ModelCheckpointNotFoundError):
        Detector.load(tmp_path, "logreg")
    meta = json.loads((tmp_path / "random_forest.json").read_text())
    meta["preprocessing_version"] = "prep-1-000000000000"
    (tmp_path / "random_forest.json").write_text(json.dumps(meta))
    with pytest.raises(ModelCheckpointNotFoundError, match="version"):
        Detector.load(tmp_path, "random_forest")


def test_binary_metrics_hand_calculated() -> None:
    y = np.array([0, 0, 0, 1, 1])
    p = np.array([0.1, 0.6, 0.2, 0.9, 0.4])
    m = binary_metrics(y, p, 0.5)
    c = m.confusion
    assert (c.true_negative, c.false_positive, c.false_negative, c.true_positive) == (2, 1, 1, 1)
    assert m.accuracy == pytest.approx(0.6) and m.precision == pytest.approx(0.5)
    assert m.recall == pytest.approx(0.5) and m.f1 == pytest.approx(0.5)
    assert m.benign_false_positive_rate == pytest.approx(1 / 3)
    assert m.malicious_detection_rate == pytest.approx(0.5)
    assert m.roc_auc == pytest.approx(5 / 6)
    assert m.pr_auc is not None and 0 < m.pr_auc <= 1
    single = binary_metrics(np.array([0, 0]), np.array([0.2, 0.7]), 0.5)
    assert single.roc_auc is None and single.pr_auc is None
    assert single.malicious_detection_rate is None
    assert binary_metrics(np.array([1]), np.array([0.2]), 0.5).benign_false_positive_rate is None
    for bad in (np.array([0.5, 1.5]), np.array([np.nan, 0.2])):
        with pytest.raises(ValueError):
            binary_metrics(np.array([0, 1]), bad, 0.5)
    with pytest.raises(ValueError):
        binary_metrics(np.array([0, 1]), np.array([0.1]), 0.5)


def test_evaluate_block_per_label_and_day(frames: Frames) -> None:
    _, test = frames
    p = test["is_malicious"].to_numpy(dtype=float)  # perfect scores
    block = evaluate_block(
        test,
        p,
        model="m",
        feature_set=FULL,
        subset=ALL_TEST,
        dataset_version="v",
        feature_version="f",
        threshold=0.5,
    )
    assert block.metrics.f1 == 1.0
    assert block.per_label_detection["DDoS"]["predicted_malicious_rate"] == 1.0
    assert block.per_label_detection["BENIGN"]["predicted_malicious_rate"] == 0.0
    assert set(block.per_day) == {"Thursday", "Friday"}


# --- experiment + tracking --------------------------------------------------------------------


def test_experiment_and_tracking(tmp_path: Path, dataset: CicDataset) -> None:
    result = run_detection_experiment(dataset, config(), "test-v1")
    assert [fs.name for fs in result.feature_sets] == [FULL, NO_DSTPORT]
    blocks = [(b.feature_set, b.model, b.subset) for fs in result.feature_sets for b in fs.blocks]
    assert (FULL, "random_forest", ALL_TEST) in blocks
    assert (NO_DSTPORT, "logreg", NO_CROSS_DUP) in blocks
    assert len(blocks) == 2 * 2 * 2
    assert set(result.class_distribution["train"]) == {"BENIGN", "DoS Hulk", "FTP-Patator"}
    assert set(result.class_distribution["test"]) == {"BENIGN", "DDoS", "Web Attack - XSS"}
    prov = DetectionProvenance(
        run_id=make_detection_run_id(),
        created_at=utc_now(),
        git_commit="c" * 40,
        git_dirty=True,
        environment=environment_info(),
        runtime_s=1.0,
        config_path="configs/classical_detection.yaml",
        manifest_entry=None,
        model_dir=None,
    )
    run_dir = write_detection_run(tmp_path, config(), dataset, result, prov)
    assert sorted(p.name for p in run_dir.iterdir()) == sorted(RUN_FILES)
    summary = (run_dir / "summary.md").read_text()
    for marker in ("TRAIN days", "TEST days", "absent from the training", "NOT ATT&CK"):
        assert marker in summary
    assert "DROPPED_IDENTIFIER_FEATURES" in summary
    preds = json.loads((run_dir / "predictions.json").read_text())
    assert len(preds["columns"]["raw_label"]) == len(result.test_frame)
    assert "p_malicious_random_forest" in preds["columns"]
    assert preds["detection_result_examples"][0]["dataset_label"] is not None
    metrics = json.loads((run_dir / "metrics.json").read_text())
    assert metrics["duplicate_audit"][FULL]["test_rows"] == len(result.test_frame)
    record = detection_record(config(), result, prov, run_dir)
    assert not set(record.train_sources) & set(record.test_sources)
    assert isinstance(record, EvaluationResult) and record.task.value == "detection"
    with SQLiteStore(":memory:") as store:
        assert store_detection_record(store, record) == record
        with pytest.raises(StorageError):
            store_detection_record(store, record)


def test_detection_config_loading(tmp_path: Path) -> None:
    path = PROJECT_ROOT / "configs" / "classical_detection.yaml"
    real = load_detection_config(path)
    assert real.train_days == TRAIN_DAYS and real.test_days == TEST_DAYS
    assert [m.name for m in real.models] == ["logreg", "random_forest"]
    text = path.read_text()
    bad = tmp_path / "bad.yaml"
    bad.write_text(text.replace("run_rbf_svm: false", "run_rbf_svm: true"))
    with pytest.raises(ConfigurationError):
        load_detection_config(bad)
    bad.write_text("seed: [unclosed")
    with pytest.raises(ConfigurationError):
        load_detection_config(bad)
    custom = tmp_path / "t.yaml"
    custom.write_text(text.replace("threshold: 0.5", "threshold: 0.7"))
    assert all(m.threshold == 0.7 for m in load_detection_config(custom).models)


def test_model_config_validation() -> None:
    with pytest.raises(ValueError):
        ModelConfig.model_validate({"name": "svm", "seed": 1})


# --- registration -----------------------------------------------------------------------------


def test_registration_extracts_csvs_safely(tmp_path: Path) -> None:
    source = write_day_files(tmp_path / "src", rows_per_label=2)
    archive = tmp_path / "raw" / "GeneratedLabelledFlows.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zf:
        for p in sorted(source.iterdir()):
            zf.write(p, f"TrafficLabelling /{p.name}")
        zf.writestr("TrafficLabelling /readme.txt", "ignored")
        zf.writestr("__MACOSX/._Monday.csv", "ignored")
    out = extract_csvs(archive, tmp_path / "external")
    assert [p.name for p in out] == sorted(p.name for p in source.iterdir())
    assert out[0].read_bytes() == (source / out[0].name).read_bytes()
    raw, csvs = manifest_entries(archive, out, tmp_path)
    assert raw.sha256 and len(csvs.files) == 5 and csvs.inputs == [raw.artifact_id]
    assert raw.local_path == "raw/GeneratedLabelledFlows.zip"
    with pytest.raises(MalformedSourceDataError):
        safe_member_path("../evil.csv", tmp_path)
    with pytest.raises(MalformedSourceDataError):
        safe_member_path("/abs/evil.csv", tmp_path)
    with pytest.raises(DatasetNotFoundError):
        extract_csvs(tmp_path / "missing.zip", tmp_path / "x")
    not_zip = tmp_path / "bad.zip"
    not_zip.write_text("nope")
    with pytest.raises(MalformedSourceDataError):
        extract_csvs(not_zip, tmp_path / "x")
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("readme.txt", "x")
    with pytest.raises(MalformedSourceDataError):
        extract_csvs(empty, tmp_path / "y")
