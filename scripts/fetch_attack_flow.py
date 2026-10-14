"""Download the official MITRE CTID Attack Flow corpus as STIX 2.1 JSON.

Usage:
    python scripts/fetch_attack_flow.py

Source of truth:
- Corpus document list: ``corpus/*.afb`` in center-for-threat-informed-defense/attack-flow
  at the current ``main`` commit (the commit SHA is recorded).
- STIX 2.1 exports: the project's official site, ``.../attack-flow/corpus/<name>.json``,
  which is built from ``main``. The site is not version-pinned, so every file's SHA-256
  is recorded and the raw files are kept locally (git-ignored).
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from hqc.common.download import download_file, fetch_json
from hqc.common.logging import configure_logging
from hqc.common.provenance import (
    ArtifactKind,
    ManifestArtifact,
    ManifestFile,
    load_manifest,
    save_manifest,
)
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.mitre.paths import RAW_ATTACK_FLOW_ARTIFACT_ID, manifest_path, raw_attack_flow_dir
from hqc.mitre.sources import (
    ATTACK_FLOW_LICENSE,
    ATTACK_FLOW_LICENSE_URL,
    ATTACK_FLOW_REPO_API,
    ATTACK_FLOW_SITE_CORPUS,
)


def corpus_document_names(commit_sha: str) -> list[str]:
    listing: list[dict[str, Any]] = fetch_json(
        f"{ATTACK_FLOW_REPO_API}/contents/corpus?ref={commit_sha}"
    )
    return sorted(e["name"][: -len(".afb")] for e in listing if e["name"].endswith(".afb"))


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=False)
    head = fetch_json(f"{ATTACK_FLOW_REPO_API}/commits/main")
    commit_sha: str = head["sha"]
    commit_date: str = head["commit"]["committer"]["date"]
    names = corpus_document_names(commit_sha)

    out_dir = raw_attack_flow_dir(settings)
    retrieved_at = utc_now()
    files: list[ManifestFile] = []
    for name in names:
        url = ATTACK_FLOW_SITE_CORPUS + urllib.parse.quote(f"{name}.json")
        dest = out_dir / f"{name}.json"
        digest = download_file(url, dest)
        files.append(
            ManifestFile(
                name=dest.name, source_url=url, sha256=digest, size_bytes=dest.stat().st_size
            )
        )

    manifest = load_manifest(manifest_path(settings))
    manifest.upsert(
        ManifestArtifact(
            artifact_id=RAW_ATTACK_FLOW_ARTIFACT_ID,
            kind=ArtifactKind.RAW,
            description="MITRE CTID Attack Flow corpus, STIX 2.1 exports (one file per flow)",
            version=f"main@{commit_sha[:12]}",
            local_path=str(out_dir.relative_to(PROJECT_ROOT)),
            size_bytes=sum(f.size_bytes for f in files),
            source_url=ATTACK_FLOW_SITE_CORPUS,
            upstream_ref=commit_sha,
            release_modified=commit_date,
            retrieved_at=retrieved_at,
            license=ATTACK_FLOW_LICENSE,
            license_url=ATTACK_FLOW_LICENSE_URL,
            files=files,
            notes=(
                "Document list from corpus/*.afb at upstream_ref; STIX files from the official "
                "project site (built from main, not version-pinned). Latest tagged release at "
                "retrieval: v3.2.0 (corpus files changed after that tag)."
            ),
        )
    )
    save_manifest(manifest, manifest_path(settings))
    total = sum(f.size_bytes for f in files)
    print(f"Attack Flow: {len(files)} documents, {total} bytes, upstream main@{commit_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
