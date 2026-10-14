"""Register a manually downloaded CIC-IDS2017 archive (no network access).

The official download requires a registration form, so the user downloads
``GeneratedLabelledFlows.zip`` from UNB/CIC and places it in ``data/raw/cicids2017/``.
This module verifies the archive, extracts only CSV members safely (no absolute paths,
no ``..``), and records provenance (source, retrieval date, SHA-256 per file) in the
tracked data manifest. Raw and extracted data stay git-ignored.
"""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from hqc.common.errors import DatasetNotFoundError, MalformedSourceDataError
from hqc.common.provenance import ArtifactKind, ManifestArtifact, ManifestFile, sha256_file

CIC_ARCHIVE_NAME = "GeneratedLabelledFlows.zip"
CIC_DATASET_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
CIC_DOWNLOAD_PAGE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017/"
CIC_RAW_ARTIFACT_ID = "cicids2017-generated-labelled-flows-zip"
CIC_EXTRACTED_ARTIFACT_ID = "cicids2017-generated-labelled-flows-csv"
CIC_LICENSE = (
    "Publicly available to researchers (UNB CIC). Users must cite: I. Sharafaldin, "
    "A. Habibi Lashkari, A. A. Ghorbani, 'Toward Generating a New Intrusion Detection Dataset "
    "and Intrusion Traffic Characterization', ICISSP 2018."
)


def safe_member_path(name: str, destination: Path) -> Path | None:
    """Destination path for a CSV member, or None to skip; raises on unsafe names."""
    member = PurePosixPath(name)
    if member.is_absolute() or ".." in member.parts:
        raise MalformedSourceDataError(f"Unsafe path in archive: {name}")
    if name.endswith("/") or member.suffix.lower() != ".csv" or member.name.startswith("._"):
        return None
    return destination / member.name


def extract_csvs(archive: Path, destination: Path) -> list[Path]:
    """Extract CSV members (flattened) and return their paths in sorted order."""
    if not archive.is_file():
        raise DatasetNotFoundError(
            f"{archive} not found. Download {CIC_ARCHIVE_NAME} from {CIC_DATASET_PAGE} "
            "(registration form) and place it there."
        )
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise MalformedSourceDataError(f"{archive} is not a valid zip archive") from exc
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            target = safe_member_path(info.filename, destination)
            if target is None:
                continue
            if target in written:
                raise MalformedSourceDataError(f"Duplicate CSV name in archive: {target.name}")
            with zf.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            written.append(target)
    if not written:
        raise MalformedSourceDataError(f"No CSV files found in {archive}")
    return sorted(written)


def manifest_entries(
    archive: Path, extracted: list[Path], project_root: Path
) -> tuple[ManifestArtifact, ManifestArtifact]:
    retrieved = datetime.fromtimestamp(archive.stat().st_mtime, tz=UTC)
    archive_sha = sha256_file(archive)
    raw = ManifestArtifact(
        artifact_id=CIC_RAW_ARTIFACT_ID,
        kind=ArtifactKind.RAW,
        description="CIC-IDS2017 GeneratedLabelledFlows.zip (official UNB/CIC distribution)",
        version="CIC-IDS2017 (UNB CIC, July 2017 capture)",
        local_path=str(archive.relative_to(project_root)),
        sha256=archive_sha,
        size_bytes=archive.stat().st_size,
        source_url=CIC_DOWNLOAD_PAGE,
        retrieved_at=retrieved,
        license=CIC_LICENSE,
        license_url=CIC_DATASET_PAGE,
        notes="Downloaded manually by the user via the official registration form; "
        "retrieved_at is the archive's file modification time.",
    )
    files = [
        ManifestFile(name=p.name, sha256=sha256_file(p), size_bytes=p.stat().st_size)
        for p in extracted
    ]
    csvs = ManifestArtifact(
        artifact_id=CIC_EXTRACTED_ARTIFACT_ID,
        kind=ArtifactKind.PROCESSED,
        description="CSV files extracted unchanged from GeneratedLabelledFlows.zip",
        version=f"zip-sha256-{archive_sha[:12]}",
        local_path=str(extracted[0].parent.relative_to(project_root)),
        size_bytes=sum(f.size_bytes for f in files),
        processed_at=datetime.now(UTC),
        processing_version="extract-csv-v1",
        inputs=[CIC_RAW_ARTIFACT_ID],
        license=CIC_LICENSE,
        files=files,
    )
    return raw, csvs
