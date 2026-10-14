"""Official ATT&CK / Attack Flow source definitions and release-index handling.

Network access lives in :mod:`hqc.common.download`; everything here is pure so it
can be tested offline.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from hqc.common.errors import MalformedSourceDataError, UnsupportedAttackVersionError
from hqc.common.schemas.base import HQCModel, NonEmptyStr

ATTACK_STIX_INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
)
ATTACK_LICENSE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt"
)
ATTACK_LICENSE_SUMMARY = (
    "MITRE ATT&CK Terms of Use: non-exclusive, royalty-free license for research, development "
    "and commercial use; copies must reproduce MITRE's copyright designation and license. "
    '"(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the '
    'permission of The MITRE Corporation."'
)
ENTERPRISE_COLLECTION_NAME = "Enterprise ATT&CK"

ATTACK_FLOW_REPO_API = "https://api.github.com/repos/center-for-threat-informed-defense/attack-flow"
ATTACK_FLOW_SITE_CORPUS = "https://center-for-threat-informed-defense.github.io/attack-flow/corpus/"
ATTACK_FLOW_LICENSE = "Apache-2.0 (center-for-threat-informed-defense/attack-flow)"
ATTACK_FLOW_LICENSE_URL = (
    "https://github.com/center-for-threat-informed-defense/attack-flow/blob/main/LICENSE"
)


class AttackRelease(HQCModel):
    """One published ATT&CK collection version from the official index."""

    collection: NonEmptyStr
    version: NonEmptyStr
    url: NonEmptyStr
    modified: NonEmptyStr


def list_enterprise_releases(index: dict[str, Any]) -> list[AttackRelease]:
    """Parse the official ``index.json`` into Enterprise releases (index order)."""
    try:
        collections = index["collections"]
        enterprise = next(c for c in collections if c.get("name") == ENTERPRISE_COLLECTION_NAME)
        return [
            AttackRelease(
                collection=ENTERPRISE_COLLECTION_NAME,
                version=v["version"],
                url=v["url"],
                modified=v["modified"],
            )
            for v in enterprise["versions"]
        ]
    except (KeyError, TypeError, StopIteration, ValidationError) as exc:
        raise MalformedSourceDataError(f"Unexpected ATT&CK index structure: {exc!r}") from exc


def select_release(index: dict[str, Any], version: str) -> AttackRelease:
    """Return the requested Enterprise release or fail listing what is available.

    The version is never substituted silently.
    """
    releases = list_enterprise_releases(index)
    for release in releases:
        if release.version == version:
            return release
    available = ", ".join(r.version for r in releases[:10])
    raise UnsupportedAttackVersionError(
        f"ATT&CK Enterprise {version} is not in the official index. "
        f"Most recent available: {available}"
    )
