from __future__ import annotations

import json


def test_disabled_update_manifest_fails_closed():
    from bioaegis.updates import verify_manifest

    assert verify_manifest({"enabled": False}) is False


def test_malformed_update_signature_fails_closed():
    from bioaegis.updates import verify_manifest

    payload = {
        "enabled": True,
        "version": "9.9.9",
        "artifact_url": "https://example.invalid/bioaegis.whl",
        "sha256": "0" * 64,
        "notes": "fixture",
        "signature": "not-a-valid-ed25519-signature",
    }
    assert verify_manifest(payload) is False


def test_manifest_canonicalization_is_deterministic():
    from bioaegis.updates import _canonical_manifest

    payload = {
        "enabled": True,
        "version": "0.7.0",
        "artifact_url": "https://example.invalid/a.whl",
        "sha256": "0" * 64,
        "notes": "fixture",
        "signature": "ignored",
    }
    canonical = _canonical_manifest(payload)
    assert canonical == _canonical_manifest(json.loads(canonical.decode("utf-8")) | {"signature": "changed"})
    assert b'"signature"' not in canonical
