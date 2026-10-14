"""Parse the downloaded Attack Flow corpus into ordered sequences.

Usage:
    python scripts/build_attack_flow_corpus.py

Outputs:
- data/processed/attack_flow/sequences.json   (PROCESSED, git-ignored)
- reports/datasets/attack_flow_corpus_summary.json (small summary, tracked)
"""

from __future__ import annotations

from hqc.common.errors import MalformedSourceDataError
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
from hqc.mitre.attack_flow import PARSER_VERSION
from hqc.mitre.attack_flow_corpus import build_corpus, write_json
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import (
    PROCESSED_ATTACK_FLOW_ARTIFACT_ID,
    RAW_ATTACK_FLOW_ARTIFACT_ID,
    manifest_path,
    processed_attack_flow_path,
    processed_kb_artifact_id,
    raw_attack_flow_dir,
)


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=False)
    manifest = load_manifest(manifest_path(settings))
    raw = manifest.get(RAW_ATTACK_FLOW_ARTIFACT_ID)
    if raw is None:
        raise SystemExit("Attack Flow corpus not in manifest; run scripts/fetch_attack_flow.py")
    stix_dir = raw_attack_flow_dir(settings)
    for f in raw.files:
        if sha256_file(stix_dir / f.name) != f.sha256:
            raise MalformedSourceDataError(f"Checksum mismatch for {f.name}; re-download")

    kb = AttackKnowledgeBase.load(settings)
    corpus = build_corpus(stix_dir, source_version=raw.version, kb=kb)

    out_path = processed_attack_flow_path(settings)
    write_json(corpus, out_path, compact=True)
    summary_path = (
        settings.resolve(settings.reports_dir) / "datasets" / ("attack_flow_corpus_summary.json")
    )
    write_json(corpus.summary, summary_path)

    manifest.upsert(
        ManifestArtifact(
            artifact_id=PROCESSED_ATTACK_FLOW_ARTIFACT_ID,
            kind=ArtifactKind.PROCESSED,
            description="Ordered technique sequences extracted from the Attack Flow corpus",
            version=raw.version,
            local_path=str(out_path.relative_to(PROJECT_ROOT)),
            sha256=sha256_file(out_path),
            size_bytes=out_path.stat().st_size,
            processed_at=utc_now(),
            processing_version=f"attack-flow-parser-{PARSER_VERSION}",
            inputs=[RAW_ATTACK_FLOW_ARTIFACT_ID, processed_kb_artifact_id(settings.attack_version)],
            license=raw.license,
            license_url=raw.license_url,
            notes=f"Summary: {summary_path.relative_to(PROJECT_ROOT)}",
        )
    )
    save_manifest(manifest, manifest_path(settings))
    s = corpus.summary
    print(
        f"{s.documents_included}/{s.documents_total} documents, {s.source_groups} groups, "
        f"{s.sequences} sequences, {s.unique_attack_technique_ids} unique ATT&CK IDs -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
