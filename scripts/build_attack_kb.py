"""Build the processed ATT&CK knowledge base from the downloaded RAW bundle.

Usage:
    python scripts/build_attack_kb.py [--version 19.2]
"""

from __future__ import annotations

import argparse

from hqc.common.logging import configure_logging
from hqc.common.provenance import (
    ArtifactKind,
    ManifestArtifact,
    load_manifest,
    save_manifest,
    sha256_file,
)
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.mitre.build import build_kb_file
from hqc.mitre.models import KB_FORMAT_VERSION
from hqc.mitre.paths import (
    manifest_path,
    processed_kb_artifact_id,
    processed_kb_path,
    raw_attack_artifact_id,
    raw_attack_path,
)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=settings.attack_version)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)

    manifest = load_manifest(manifest_path(settings))
    raw_entry = manifest.get(raw_attack_artifact_id(args.version))
    raw_path = raw_attack_path(settings, args.version)
    if raw_entry is not None and raw_entry.sha256 != sha256_file(raw_path):
        raise SystemExit(f"Checksum mismatch for {raw_path}; re-run scripts/fetch_attack.py")

    out_path = processed_kb_path(settings, args.version)
    data = build_kb_file(
        raw_path, out_path, args.version, source_url=raw_entry.source_url if raw_entry else None
    )
    manifest.upsert(
        ManifestArtifact(
            artifact_id=processed_kb_artifact_id(args.version),
            kind=ArtifactKind.PROCESSED,
            description="Normalised ATT&CK Enterprise knowledge base (hqc.mitre.models)",
            version=args.version,
            local_path=str(out_path.relative_to(PROJECT_ROOT)),
            sha256=sha256_file(out_path),
            size_bytes=out_path.stat().st_size,
            processed_at=utc_now(),
            processing_version=f"kb-format-{KB_FORMAT_VERSION}",
            inputs=[raw_attack_artifact_id(args.version)],
            license=raw_entry.license if raw_entry else None,
            license_url=raw_entry.license_url if raw_entry else None,
            notes="Derived data. Contains MITRE ATT&CK content; reproduce the MITRE notice.",
        )
    )
    save_manifest(manifest, manifest_path(settings))
    print(f"KB {args.version}: {data.metadata.counts} -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
