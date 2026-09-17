"""Installation integrity manifest for BIOAEGIS tamper detection."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .integrity import sign, verify

MANIFEST_NAME = ".integrity-manifest.json"
SIGNATURE_NAME = ".integrity-manifest.sig"
CRITICAL_DIRS = ("bioaegis", "service", "assets")
CRITICAL_FILES = ("pyproject.toml",)


def manifest_path(root: str | Path) -> Path:
    return Path(root) / MANIFEST_NAME


def signature_path(root: str | Path) -> Path:
    return Path(root) / SIGNATURE_NAME


def _files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for relative in CRITICAL_FILES:
        candidate = root / relative
        if candidate.is_file():
            paths.append(candidate)
    for directory in CRITICAL_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and not path.is_symlink():
                paths.append(path)
    return sorted(set(paths))


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass


def write_manifest(root: str | Path, key_path: str | Path | None = None) -> Path:
    root_path = Path(root).resolve()
    data = {
        "version": 1,
        "files": {
            str(path.relative_to(root_path)): _digest(path)
            for path in _files(root_path)
        },
    }
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    key = Path(key_path or os.environ.get("BIOAEGIS_INTEGRITY_KEY", Path.home() / ".local" / "share" / "bioaegis" / "integrity.key"))
    _atomic(manifest_path(root_path), payload)
    _atomic(signature_path(root_path), (sign(payload, key) + "\n").encode("ascii"))
    return manifest_path(root_path)


def verify_manifest(root: str | Path, key_path: str | Path | None = None) -> tuple[bool, tuple[str, ...]]:
    root_path = Path(root).resolve()
    manifest = manifest_path(root_path)
    signature = signature_path(root_path)
    key = Path(key_path or os.environ.get("BIOAEGIS_INTEGRITY_KEY", Path.home() / ".local" / "share" / "bioaegis" / "integrity.key"))
    try:
        payload = manifest.read_bytes()
        sig = signature.read_text(encoding="ascii").strip()
        if not verify(payload, sig, key):
            return False, ("installation manifest signature mismatch",)
        data = json.loads(payload.decode("utf-8"))
        expected = data.get("files", {})
        if not isinstance(expected, dict):
            return False, ("invalid installation manifest",)
        issues: list[str] = []
        for relative, digest in expected.items():
            path = root_path / relative
            if not path.is_file():
                issues.append(f"missing: {relative}")
                continue
            actual = _digest(path)
            if actual != digest:
                issues.append(f"modified: {relative}")
        return not issues, tuple(issues)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False, ("installation manifest unavailable or malformed",)
