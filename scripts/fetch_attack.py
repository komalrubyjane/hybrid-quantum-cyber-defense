"""Download the official MITRE ATT&CK Enterprise STIX bundle for a version.

Usage:
    python scripts/fetch_attack.py [--version 19.2]

Steps: read the official release index -> verify the version is published (fail
otherwise; never substitute) -> download the bundle -> record provenance in
data/MANIFEST.yaml. The raw file is git-ignored.
"""

from __future__ import annotations

import argparse
import sys

from hqc.common.download import download_file, fetch_json
from hqc.common.errors import UnsupportedAttackVersionError
from hqc.common.logging import configure_logging
from hqc.common.provenance import (
    ArtifactKind,
    ManifestArtifact,
    load_manifest,
    save_manifest,
)
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.mitre.paths import manifest_path, raw_attack_artifact_id, raw_attack_path
from hqc.mitre.sources import (
    ATTACK_LICENSE_SUMMARY,
    ATTACK_LICENSE_URL,
    ATTACK_STIX_INDEX_URL,
    select_release,
)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=settings.attack_version)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)

    index = fetch_json(ATTACK_STIX_INDEX_URL)
    try:
        release = select_release(index, args.version)
    except UnsupportedAttackVersionError as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2

    dest = raw_attack_path(settings, release.version)
    retrieved_at = utc_now()
    digest = download_file(release.url, dest)
    size = dest.stat().st_size

    manifest = load_manifest(manifest_path(settings))
    manifest.upsert(
        ManifestArtifact(
            artifact_id=raw_attack_artifact_id(release.version),
            kind=ArtifactKind.RAW,
            description="MITRE ATT&CK Enterprise STIX 2.1 bundle (official attack-stix-data)",
            version=release.version,
            local_path=str(dest.relative_to(PROJECT_ROOT)),
            sha256=digest,
            size_bytes=size,
            source_url=release.url,
            release_modified=release.modified,
            retrieved_at=retrieved_at,
            license=ATTACK_LICENSE_SUMMARY,
            license_url=ATTACK_LICENSE_URL,
            notes=f"Version verified against official index {ATTACK_STIX_INDEX_URL}",
        )
    )
    save_manifest(manifest, manifest_path(settings))
    print(f"ATT&CK Enterprise {release.version} -> {dest} ({size} bytes) sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
