"""Reversible, user-local quarantine for suspicious files."""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class QuarantineRecord:
    original_path: str
    quarantine_path: str
    sha256: str
    timestamp: float


class Quarantine:
    """Move a file out of its original location without deleting it."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path.home() / ".local/share/bioaegis/quarantine").expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.index = self.root / "index.json"

    def isolate(self, path: str | Path, sha256: str) -> QuarantineRecord:
        source = Path(path).expanduser().resolve()
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"Not a regular file: {source}")
        if source == self.root or self.root in source.parents:
            raise ValueError("Refusing to quarantine a file already inside the quarantine directory")

        destination = self.root / f"{sha256[:16]}-{source.name}.quarantined"
        if destination.exists():
            destination = self.root / f"{sha256[:16]}-{int(time.time())}-{source.name}.quarantined"

        shutil.move(str(source), str(destination))
        os.chmod(destination, 0o600)
        record = QuarantineRecord(str(source), str(destination), sha256, time.time())
        self._append(record)
        return record

    def _append(self, record: QuarantineRecord) -> None:
        records = []
        if self.index.exists():
            try:
                records = json.loads(self.index.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                records = []
        records.append({
            "original_path": record.original_path,
            "quarantine_path": record.quarantine_path,
            "sha256": record.sha256,
            "timestamp": record.timestamp,
        })
        self.index.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        os.chmod(self.index, 0o600)

    def list(self) -> list[QuarantineRecord]:
        if not self.index.exists():
            return []
        payload = json.loads(self.index.read_text(encoding="utf-8"))
        return [QuarantineRecord(**item) for item in payload]
