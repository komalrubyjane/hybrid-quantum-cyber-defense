"""Verify, extract and record provenance for a manually downloaded CIC-IDS2017 archive.

Usage:
    python scripts/register_cicids2017.py

Expects data/raw/cicids2017/GeneratedLabelledFlows.zip (downloaded by the user from the
official UNB/CIC page). Extracts CSVs to data/external/cicids2017/ and updates
data/MANIFEST.yaml. No network access.
"""

from __future__ import annotations

from hqc.common.provenance import load_manifest, save_manifest
from hqc.config import PROJECT_ROOT, get_settings
from hqc.detection.registration import CIC_ARCHIVE_NAME, extract_csvs, manifest_entries
from hqc.mitre.paths import manifest_path


def main() -> int:
    settings = get_settings()
    data_dir = settings.resolve(settings.data_dir)
    archive = data_dir / "raw" / "cicids2017" / CIC_ARCHIVE_NAME
    extracted = extract_csvs(archive, data_dir / "external" / "cicids2017")
    raw, csvs = manifest_entries(archive, extracted, PROJECT_ROOT)
    manifest = load_manifest(manifest_path(settings))
    manifest.upsert(raw)
    manifest.upsert(csvs)
    save_manifest(manifest, manifest_path(settings))
    print(f"{archive.name}: {raw.size_bytes} bytes sha256={raw.sha256}")
    for f in csvs.files:
        print(f"  {f.name}: {f.size_bytes} bytes sha256={f.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
