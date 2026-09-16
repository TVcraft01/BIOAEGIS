"""Local integrity protection for immune-memory data and response policies."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def _key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(os.urandom(32))
        path.chmod(0o600)
    return path.read_bytes()


def sign(payload: bytes, key_path: str | Path) -> str:
    key = _key(Path(key_path))
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify(payload: bytes, signature: str, key_path: str | Path) -> bool:
    try:
        expected = sign(payload, key_path)
    except OSError:
        return False
    return hmac.compare_digest(expected, signature)
