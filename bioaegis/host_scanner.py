"""Real, read-only host scanning for BIOAEGIS.

The scanner never executes a scanned file. It collects conservative static
signals and optionally consumes ClamAV results when clamscan is installed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_ANALYSIS_BYTES = 8 * 1024 * 1024

SUSPICIOUS_PATTERNS = (
    ("download-and-execute", re.compile(rb"(?:curl|wget)[^\n]{0,300}(?:\||;)[^\n]{0,100}(?:sh|bash)")),
    ("base64-payload", re.compile(rb"base64[ \t]+(?:-d|--decode)")),
    ("reverse-shell", re.compile(rb"(?:/dev/tcp/|nc[ \t]+[^\n]{0,80}-e[ \t]+(?:/bin/)?(?:sh|bash))")),
    ("destructive-command", re.compile(rb"(?:rm[ \t]+-rf[ \t]+/|mkfs\.|dd[ \t]+if=/dev/(?:zero|random))")),
)


@dataclass(frozen=True)
class HostFinding:
    path: Path
    sha256: str
    behaviors: frozenset[str]
    score: int
    evidence: tuple[str, ...]
    clamav: str | None = None


class HostScanner:
    """Read-only scanner. It never quarantines, deletes, or executes findings."""

    def __init__(self, max_bytes: int = MAX_ANALYSIS_BYTES) -> None:
        self.max_bytes = max_bytes
        self.clamscan = shutil.which("clamscan")

    def scan(self, target: str | Path) -> list[HostFinding]:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(root)
        files = [root] if root.is_file() else self._walk(root)
        findings: list[HostFinding] = []
        for path in files:
            finding = self._inspect(path)
            if finding is not None:
                findings.append(finding)
        return findings

    def _walk(self, root: Path):
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            for name in files:
                path = Path(current) / name
                if path.is_symlink() or not path.is_file():
                    continue
                yield path

    def _inspect(self, path: Path) -> HostFinding | None:
        try:
            stat = path.stat()
            with path.open("rb") as handle:
                sample = handle.read(self.max_bytes)
        except (OSError, PermissionError):
            return None

        sha256 = hashlib.sha256(sample).hexdigest()
        behaviors: set[str] = set()
        evidence: list[str] = []
        score = 0

        if stat.st_mode & 0o111:
            behaviors.add("executable")
            evidence.append("executable permission")
        if path.name.startswith(".") and stat.st_mode & 0o111:
            behaviors.add("hidden_executable")
            evidence.append("hidden executable filename")

        for label, pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(sample):
                behaviors.add(label)
                evidence.append(label)
                score += 2

        clamav = self._clamav(path)
        if clamav:
            behaviors.add("malware_signature")
            evidence.append(f"ClamAV: {clamav}")
            score += 10

        if not behaviors or score == 0:
            return None
        return HostFinding(path, sha256, frozenset(behaviors), score, tuple(evidence), clamav)

    def _clamav(self, path: Path) -> str | None:
        if not self.clamscan:
            return None
        try:
            result = subprocess.run(
                [self.clamscan, "--infected", "--no-summary", "--", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode == 1:
            return result.stdout.strip() or "ClamAV detected a threat"
        return None
