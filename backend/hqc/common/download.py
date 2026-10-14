"""Allowlisted HTTPS downloads of official source data.

Only URL prefixes in :data:`OFFICIAL_SOURCE_PREFIXES` may be fetched. Large detection
datasets (CIC-IDS2017, UNSW-NB15) are deliberately NOT on the allowlist; adding them
requires explicit user approval.
"""

from __future__ import annotations

import json
import os
import ssl
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

import certifi

from hqc.common.errors import MalformedSourceDataError, UntrustedSourceError
from hqc.common.logging import get_logger
from hqc.common.provenance import sha256_file

log = get_logger(__name__)

OFFICIAL_SOURCE_PREFIXES: tuple[str, ...] = (
    # MITRE ATT&CK STIX data (official MITRE repository)
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/",
    # MITRE Center for Threat-Informed Defense: Attack Flow (repo, API, project site)
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-flow/",
    "https://api.github.com/repos/center-for-threat-informed-defense/attack-flow/",
    "https://center-for-threat-informed-defense.github.io/attack-flow/",
)
USER_AGENT = "hqc-research-prototype/0.1 (+defensive research; data provenance)"
DEFAULT_TIMEOUT_S = 120


def _ssl_context() -> ssl.SSLContext:
    """Certificate-verifying TLS context using the certifi CA bundle (never unverified)."""
    return ssl.create_default_context(cafile=certifi.where())


def ensure_official(url: str) -> None:
    """Raise UntrustedSourceError unless ``url`` starts with an allowlisted prefix."""
    if not url.startswith(OFFICIAL_SOURCE_PREFIXES):
        raise UntrustedSourceError(f"Refusing to download from non-allowlisted URL: {url}")


def fetch_bytes(url: str, timeout_s: int = DEFAULT_TIMEOUT_S) -> bytes:
    """GET an allowlisted URL and return the body."""
    ensure_official(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout_s, context=_ssl_context()) as response:
        body: bytes = response.read()
    log.info("fetched", extra={"stage": "ingestion", "url": url, "bytes": len(body)})
    return body


def fetch_json(url: str, timeout_s: int = DEFAULT_TIMEOUT_S) -> Any:
    """GET an allowlisted URL and parse JSON."""
    try:
        return json.loads(fetch_bytes(url, timeout_s))
    except json.JSONDecodeError as exc:
        raise MalformedSourceDataError(f"Response from {url} is not valid JSON") from exc


def download_file(url: str, dest: Path, timeout_s: int = DEFAULT_TIMEOUT_S) -> str:
    """Download to ``dest`` atomically and return its SHA-256."""
    body = fetch_bytes(url, timeout_s)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".partial-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
        Path(tmp_name).replace(dest)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return sha256_file(dest)
