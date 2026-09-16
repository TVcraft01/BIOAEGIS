"""Read-only user persistence inspection for BIOAEGIS."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PERSISTENCE_ROOTS = (
    Path("~/.config/autostart"),
    Path("~/.config/systemd/user"),
)

PERSISTENCE_FILES = (
    Path("~/.profile"),
    Path("~/.bashrc"),
    Path("~/.zshrc"),
    Path("~/.config/fish/config.fish"),
)

PATTERNS = (
    ("download-execute", re.compile(r"(?:curl|wget)[^\n]{0,240}(?:\||;)[^\n]{0,80}(?:sh|bash)\b", re.I)),
    ("encoded-command", re.compile(r"(?:base64\s+(?:-d|--decode)|python\s+-c|perl\s+-e)", re.I)),
    ("hidden-temp-execution", re.compile(r"(?:/tmp/|/var/tmp/|/dev/shm/)[^\s]+", re.I)),
    ("reverse-shell", re.compile(r"(?:/dev/tcp/|\bnc\b[^\n]{0,80}\s-e\s)", re.I)),
)


@dataclass(frozen=True)
class PersistenceFinding:
    path: Path
    signals: frozenset[str]
    evidence: tuple[str, ...]
    score: int


class PersistenceScanner:
    """Search common user startup locations without changing or executing them."""

    def scan(self) -> list[PersistenceFinding]:
        files: set[Path] = set()
        for root in PERSISTENCE_ROOTS:
            resolved = root.expanduser()
            if resolved.is_dir():
                files.update(path for path in resolved.rglob("*") if path.is_file() and not path.is_symlink())
        for item in PERSISTENCE_FILES:
            path = item.expanduser()
            if path.is_file() and not path.is_symlink():
                files.add(path)

        findings: list[PersistenceFinding] = []
        for path in sorted(files):
            finding = self._inspect(path)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _inspect(path: Path) -> PersistenceFinding | None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

        signals: set[str] = set()
        evidence: list[str] = []
        score = 0
        for label, pattern in PATTERNS:
            if pattern.search(text):
                signals.add(label)
                evidence.append(label)
                score += 2

        if not signals:
            return None
        return PersistenceFinding(path, frozenset(signals), tuple(evidence), score)
