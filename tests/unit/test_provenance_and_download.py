"""Checksums, manifest handling, release selection and allowlisted downloads."""

from __future__ import annotations

import hashlib
import io
import json
import ssl
from pathlib import Path
from typing import Any

import pytest

from hqc.common import download
from hqc.common.errors import (
    MalformedSourceDataError,
    UnsupportedAttackVersionError,
    UntrustedSourceError,
)
from hqc.common.provenance import (
    ArtifactKind,
    Manifest,
    ManifestArtifact,
    ManifestFile,
    load_manifest,
    save_manifest,
    sha256_bytes,
    sha256_file,
)
from hqc.mitre.sources import list_enterprise_releases, select_release

INDEX: dict[str, Any] = {
    "collections": [
        {"name": "Mobile ATT&CK", "versions": [{"version": "19.2", "url": "m", "modified": "x"}]},
        {
            "name": "Enterprise ATT&CK",
            "versions": [
                {"version": "19.2", "url": "https://e/19.2.json", "modified": "2026-08-05"},
                {"version": "19.1", "url": "https://e/19.1.json", "modified": "2026-05-12"},
            ],
        },
    ]
}


# --- checksums / manifest ---------------------------------------------------------------


def test_sha256_helpers(tmp_path: Path) -> None:
    data = b"attack" * 1000
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert sha256_file(path) == sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def _artifact(aid: str, **kw: Any) -> ManifestArtifact:
    return ManifestArtifact(
        artifact_id=aid,
        kind=ArtifactKind.RAW,
        description="d",
        version="1",
        local_path="data/x",
        sha256="a" * 64,
        **kw,
    )


def test_manifest_upsert_sorted_and_round_trip(tmp_path: Path) -> None:
    manifest = Manifest()
    manifest.upsert(_artifact("zeta"))
    manifest.upsert(
        _artifact("alpha", files=[ManifestFile(name="f", sha256="b" * 64, size_bytes=1)])
    )
    manifest.upsert(_artifact("zeta", notes="replaced"))
    assert [a.artifact_id for a in manifest.artifacts] == ["alpha", "zeta"]
    zeta = manifest.get("zeta")
    assert zeta is not None and zeta.notes == "replaced"
    assert manifest.get("missing") is None
    path = tmp_path / "MANIFEST.yaml"
    save_manifest(manifest, path)
    assert path.read_text().startswith("# Data manifest")
    assert load_manifest(path) == manifest


def test_manifest_missing_and_malformed(tmp_path: Path) -> None:
    assert load_manifest(tmp_path / "absent.yaml") == Manifest()
    bad = tmp_path / "bad.yaml"
    bad.write_text("artifacts: [{artifact_id: x}]")
    with pytest.raises(MalformedSourceDataError):
        load_manifest(bad)
    bad.write_text("key: [unclosed")
    with pytest.raises(MalformedSourceDataError):
        load_manifest(bad)


def test_manifest_rejects_bad_checksum() -> None:
    with pytest.raises(ValueError):
        _artifact("x").model_validate({**_artifact("x").model_dump(), "sha256": "nothex"})


# --- release index ------------------------------------------------------------------------


def test_select_release_exact_version() -> None:
    release = select_release(INDEX, "19.2")
    assert (release.version, release.url) == ("19.2", "https://e/19.2.json")
    assert [r.version for r in list_enterprise_releases(INDEX)] == ["19.2", "19.1"]


def test_unavailable_version_lists_alternatives_and_never_substitutes() -> None:
    with pytest.raises(UnsupportedAttackVersionError, match=r"19\.3.*19\.2, 19\.1"):
        select_release(INDEX, "19.3")


@pytest.mark.parametrize(
    "index", [{}, {"collections": []}, {"collections": [{"name": "Enterprise ATT&CK"}]}]
)
def test_malformed_index(index: dict[str, Any]) -> None:
    with pytest.raises(MalformedSourceDataError):
        list_enterprise_releases(index)


# --- downloads ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://www.unb.ca/cic/datasets/ids-2017.html",  # large dataset: requires approval
        "https://evil.example/attack-stix-data/enterprise-attack.json",
        "http://raw.githubusercontent.com/mitre-attack/attack-stix-data/x",  # not https
        "https://raw.githubusercontent.com/someone-else/attack-stix-data/x",
    ],
)
def test_non_official_urls_rejected(url: str) -> None:
    with pytest.raises(UntrustedSourceError):
        download.fetch_bytes(url)


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


OFFICIAL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"


def test_fetch_and_download_with_mocked_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[Any] = []

    def fake_urlopen(request: Any, timeout: int, context: ssl.SSLContext) -> _FakeResponse:
        calls.append((request.full_url, context))
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(download.urllib.request, "urlopen", fake_urlopen)
    assert download.fetch_json(OFFICIAL) == {"ok": True}
    dest = tmp_path / "sub" / "index.json"
    digest = download.download_file(OFFICIAL, dest)
    assert dest.read_bytes() == b'{"ok": true}'
    assert digest == sha256_bytes(dest.read_bytes())
    assert not list(dest.parent.glob(".partial-*"))  # atomic write leaves no temp files
    context = calls[0][1]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_fetch_json_rejects_non_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        download.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(b"<html>")
    )
    with pytest.raises(MalformedSourceDataError):
        download.fetch_json(OFFICIAL)


def test_failed_download_leaves_no_partial_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(download, "fetch_bytes", lambda url, timeout_s=0: b"data")

    def boom(self: Path, target: Path) -> Path:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", boom)
    with pytest.raises(OSError):
        download.download_file(OFFICIAL, tmp_path / "x.json")
    assert list(tmp_path.iterdir()) == []
