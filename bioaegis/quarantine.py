"""Reversible, user-local quarantine for suspicious files."""

from __future__ import annotations

import hashlib
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
    restored_at: float | None = None


class Quarantine:
    """Move files aside safely and support verified rollback."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path.home() / ".local/share/bioaegis/quarantine").expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.index = self.root / "index.json"

    def isolate(self, path: str | Path, sha256: str) -> QuarantineRecord:
        source = Path(path).expanduser().resolve()
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"Not a regular file: {source}")
        if source == self.root or self.root in source.parents:
            raise ValueError("Refusing to quarantine a file already inside the quarantine directory")
        actual_sha = self._hash_file(source)
        if actual_sha != sha256:
            raise ValueError("File changed before quarantine; refusing to isolate it")

        destination = self.root / f"{sha256[:16]}-{source.name}.quarantined"
        if destination.exists():
            destination = self.root / f"{sha256[:16]}-{int(time.time())}-{source.name}.quarantined"

        shutil.move(str(source), str(destination))
        os.chmod(destination, 0o600)
        record = QuarantineRecord(str(source), str(destination), sha256, time.time())
        self._append(record)
        return record

    def restore(self, quarantine_path: str | Path) -> QuarantineRecord:
        selected = Path(quarantine_path).expanduser()
        if not selected.is_absolute():
            selected = self.root / selected
        selected = selected.resolve()
        if selected == self.root or self.root not in selected.parents:
            raise ValueError("Refusing to restore a path outside the quarantine directory")
        if not selected.is_file() or selected.is_symlink():
            raise FileNotFoundError(selected)

        records = self.list()
        record = next((item for item in records if Path(item.quarantine_path).resolve() == selected), None)
        if record is None:
            raise ValueError(f"No quarantine record found for {selected}")
        if record.restored_at is not None:
            raise ValueError("This quarantine record has already been restored")

        actual_sha = self._hash_file(selected)
        if actual_sha != record.sha256:
            raise ValueError("Quarantined file hash mismatch; refusing to restore it")

        destination = Path(record.original_path).expanduser().resolve()
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"Restore destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(selected), str(destination))
        os.chmod(destination, 0o600)
        restored_sha = self._hash_file(destination)
        if restored_sha != record.sha256:
            raise OSError("Restore verification failed: SHA-256 changed")

        updated = [
            QuarantineRecord(
                item.original_path,
                item.quarantine_path,
                item.sha256,
                item.timestamp,
                time.time() if item == record else item.restored_at,
            )
            for item in records
        ]
        self._write(updated)
        return next(item for item in updated if item.quarantine_path == record.quarantine_path)

    def _append(self, record: QuarantineRecord) -> None:
        records = self.list()
        records.append(record)
        self._write(records)

    def _write(self, records: list[QuarantineRecord]) -> None:
        payload = [
            {
                "original_path": item.original_path,
                "quarantine_path": item.quarantine_path,
                "sha256": item.sha256,
                "timestamp": item.timestamp,
                "restored_at": item.restored_at,
            }
            for item in records
        ]
        self.index.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(self.index, 0o600)

    def list(self) -> list[QuarantineRecord]:
        if not self.index.exists():
            return []
        try:
            payload = json.loads(self.index.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise OSError(f"Cannot read quarantine index: {self.index}") from exc
        records: list[QuarantineRecord] = []
        for item in payload:
            records.append(
                QuarantineRecord(
                    original_path=item["original_path"],
                    quarantine_path=item["quarantine_path"],
                    sha256=item["sha256"],
                    timestamp=float(item["timestamp"]),
                    restored_at=float(item["restored_at"]) if item.get("restored_at") is not None else None,
                )
            )
        return records

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
