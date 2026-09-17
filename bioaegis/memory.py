"""Protected immune memory: store validated responses, not investigators."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
import tempfile
from pathlib import Path

from .integrity import sign, verify
from .models import Countermeasure


class ImmuneMemory:
    """JSON-backed memory with fail-closed HMAC integrity verification."""

    def __init__(self, path: str | Path = "memory/countermeasures.json", key_path: str | Path | None = None) -> None:
        self.path = Path(path)
        self.signature_path = self.path.with_suffix(self.path.suffix + ".sig")
        default_key = Path.home() / ".local" / "share" / "bioaegis" / "integrity.key"
        self.key_path = Path(key_path or os.environ.get("BIOAEGIS_INTEGRITY_KEY", default_key))
        self._entries: list[Countermeasure] = []

    def remember(self, countermeasure: Countermeasure) -> None:
        if countermeasure not in self._entries:
            self._entries.append(countermeasure)

    def match(self, behavior: set[str] | frozenset[str]) -> Countermeasure | None:
        incoming = set(behavior)
        matches = [entry for entry in self._entries if entry.trigger.issubset(incoming)]
        if not matches:
            return None
        return max(matches, key=lambda entry: (len(entry.trigger), entry.name))

    def _payload(self) -> bytes:
        entries = [
            {
                **asdict(entry),
                "trigger": sorted(entry.trigger),
                "actions": list(entry.actions),
            }
            for entry in self._entries
        ]
        return (json.dumps(entries, indent=2, sort_keys=True) + "\n").encode("utf-8")

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
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

    def save(self) -> None:
        payload = self._payload()
        signature = (sign(payload, self.key_path) + "\n").encode("ascii")
        self._atomic_write(self.path, payload)
        self._atomic_write(self.signature_path, signature)

    def load(self) -> None:
        if not self.path.exists():
            self._entries = []
            return
        try:
            payload_bytes = self.path.read_bytes()
            signature = self.signature_path.read_text(encoding="ascii").strip()
            if not signature or not verify(payload_bytes, signature, self.key_path):
                self._entries = []
                return
            payload = json.loads(payload_bytes.decode("utf-8"))
            if not isinstance(payload, list):
                raise ValueError("immune memory must be a list")

            entries: list[Countermeasure] = []
            for item in payload:
                if not isinstance(item, dict):
                    raise ValueError("invalid immune memory entry")
                trigger = item["trigger"]
                actions = item["actions"]
                if not isinstance(trigger, list) or not isinstance(actions, list):
                    raise ValueError("invalid immune memory fields")
                if not all(isinstance(value, str) for value in trigger + actions):
                    raise ValueError("immune memory fields must contain strings")
                entries.append(
                    Countermeasure(
                        name=str(item["name"]),
                        trigger=frozenset(trigger),
                        actions=tuple(actions),
                        rationale=str(item["rationale"]),
                    )
                )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            self._entries = []
            return

        self._entries = entries

    @property
    def entries(self) -> tuple[Countermeasure, ...]:
        return tuple(self._entries)
