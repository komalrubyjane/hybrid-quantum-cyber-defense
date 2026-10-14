"""Build the versioned technique vocabulary from the processed ATT&CK knowledge base.

Usage:
    python scripts/build_vocabulary.py [--version 19.2]

Output (DERIVED, small, tracked in git):
    models/attack_prediction/vocabulary/technique-vocabulary-attack-<version>.json
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
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import (
    manifest_path,
    processed_kb_artifact_id,
    processed_kb_path,
    vocabulary_artifact_id,
    vocabulary_path,
)
from hqc.prediction.vocabulary import VOCABULARY_FORMAT_VERSION, TechniqueVocabulary


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=settings.attack_version)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)

    kb = AttackKnowledgeBase.from_file(processed_kb_path(settings, args.version), args.version)
    vocab = TechniqueVocabulary.from_knowledge_base(kb)
    out = vocabulary_path(settings, args.version)
    vocab.save(out)

    manifest = load_manifest(manifest_path(settings))
    manifest.upsert(
        ManifestArtifact(
            artifact_id=vocabulary_artifact_id(args.version),
            kind=ArtifactKind.DERIVED,
            description="Technique-ID vocabulary (<PAD>, <UNK>, active Enterprise techniques)",
            version=vocab.vocabulary_version,
            local_path=str(out.relative_to(PROJECT_ROOT)),
            sha256=sha256_file(out),
            size_bytes=out.stat().st_size,
            processed_at=utc_now(),
            processing_version=f"vocabulary-format-{VOCABULARY_FORMAT_VERSION}",
            inputs=[processed_kb_artifact_id(args.version)],
            notes=f"{vocab.size} tokens; content_sha256={vocab.content_sha256}",
        )
    )
    save_manifest(manifest, manifest_path(settings))
    print(f"{vocab.vocabulary_version}: {vocab.size} tokens -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
