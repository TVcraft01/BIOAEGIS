"""Secure signed update channel for BIOAEGIS releases."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

MANIFEST_URL = "https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/updates/manifest.json"
PUBLIC_KEY_FILE = Path(__file__).resolve().parent.parent / "updates" / "trusted-key.pem"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    artifact_url: str
    sha256: str
    notes: str = ""


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for part in version.lstrip("v").split("."):
        number = "".join(ch for ch in part if ch.isdigit())
        parts.append(int(number or 0))
    return tuple(parts)


def _canonical_manifest(data: dict[str, object]) -> bytes:
    signed = {key: value for key, value in data.items() if key != "signature"}
    return (json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def verify_manifest(data: dict[str, object]) -> bool:
    if not data.get("enabled", False):
        return False
    signature = data.get("signature")
    if not isinstance(signature, str) or not PUBLIC_KEY_FILE.is_file():
        return False
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(base64.b64decode(signature), _canonical_manifest(data))
        return True
    except (ValueError, TypeError, OSError):
        return False


def fetch_manifest(url: str = MANIFEST_URL) -> dict[str, object] | None:
    request = urllib.request.Request(url, headers={"User-Agent": "BIOAEGIS-Updater/1"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(MAX_MANIFEST_BYTES + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return None
    if len(body) > MAX_MANIFEST_BYTES:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def check_for_update(current_version: str, url: str = MANIFEST_URL) -> UpdateInfo | None:
    data = fetch_manifest(url)
    if data is None or not verify_manifest(data):
        return None
    version = data.get("version")
    artifact_url = data.get("artifact_url")
    digest = data.get("sha256")
    if not all(isinstance(value, str) for value in (version, artifact_url, digest)):
        return None
    if _version_tuple(version) <= _version_tuple(current_version):
        return None
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
        return None
    return UpdateInfo(version, artifact_url, digest.lower(), str(data.get("notes", "")))


def download_and_verify(update: UpdateInfo) -> Path:
    temporary = tempfile.NamedTemporaryFile(prefix="bioaegis-update-", suffix=".whl", delete=False)
    temporary_path = Path(temporary.name)
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(update.artifact_url, headers={"User-Agent": "BIOAEGIS-Updater/1"})
    try:
        with temporary:
            with urllib.request.urlopen(request, timeout=30) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_ARTIFACT_BYTES:
                        raise ValueError("update artifact exceeds configured size limit")
                    digest.update(chunk)
                    temporary.write(chunk)
        if digest.hexdigest() != update.sha256:
            raise ValueError("update artifact SHA-256 mismatch")
        return temporary_path
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def apply_wheel(wheel: Path, install_root: str | Path) -> None:
    root = Path(install_root).resolve()
    python = root / ".venv" / "bin" / "python"
    if not python.is_file():
        raise FileNotFoundError(python)
    try:
        subprocess.run(
            [str(python), "-m", "pip", "install", "--upgrade", str(wheel)],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    finally:
        wheel.unlink(missing_ok=True)
