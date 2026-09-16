"""Real, read-only host scanning for BIOAEGIS.

Normal scans are bounded and fast. Deep scans add full SHA-256 hashing and an
optional recursive ClamAV pass. Text-oriented heuristic rules are not applied
to arbitrary binary files such as ISO images. The scanner never executes a
scanned file.
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
CLAMAV_TIMEOUT_SECONDS = 30
TEXT_LIKELIHOOD_MIN = 0.85

SUSPICIOUS_PATTERNS = (
    ("download-and-execute", re.compile(rb"(?:curl|wget)[^\n]{0,300}(?:\||;)[^\n]{0,100}(?:sh|bash)")),
    ("base64-payload", re.compile(rb"base64[ \t]+(?:-d|--decode)")),
    ("reverse-shell", re.compile(rb"(?:/dev/tcp/|nc[ \t]+[^\n]{0,80}-e[ \t]+(?:/bin/)?(?:sh|bash))")),
    ("destructive-command", re.compile(rb"(?:rm[ \t]+-rf[ \t]+/|mkfs\.|dd[ \t]+if=/dev/(?:zero|random))")),
)

TEXT_EXTENSIONS = {
    ".bash", ".c", ".cc", ".cpp", ".css", ".csv", ".conf", ".fish", ".go",
    ".h", ".hpp", ".html", ".htm", ".ini", ".java", ".js", ".json", ".jsx",
    ".log", ".md", ".php", ".pl", ".py", ".rb", ".rs", ".sh", ".sql", ".svg",
    ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".zsh",
}


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

    def __init__(self, max_bytes: int = MAX_ANALYSIS_BYTES, deep: bool = False) -> None:
        self.max_bytes = max_bytes
        self.deep = deep
        self.clamscan = shutil.which("clamscan")

    def scan(self, target: str | Path) -> list[HostFinding]:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(root)
        files = [root] if root.is_file() else self._walk(root)

        clamav_hits = self._clamav(root) if self.deep and self.clamscan else {}

        findings: list[HostFinding] = []
        for path in files:
            finding = self._inspect(path, clamav_hits)
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

    def _inspect(self, path: Path, clamav_hits: dict[Path, str]) -> HostFinding | None:
        try:
            stat = path.stat()
            with path.open("rb") as handle:
                sample = handle.read(self.max_bytes)
        except (OSError, PermissionError):
            return None

        behaviors: set[str] = set()
        evidence: list[str] = []
        score = 0

        if stat.st_mode & 0o111:
            behaviors.add("executable")
            evidence.append("executable permission")
        if path.name.startswith(".") and stat.st_mode & 0o111:
            behaviors.add("hidden_executable")
            evidence.append("hidden executable filename")

        # Shell/content heuristics are only meaningful for text-like files.
        # Applying strings such as "rm -rf /" to arbitrary binary containers
        # causes false positives because binary data can coincidentally contain
        # those byte sequences. Deep mode/ClamAV remains available for binaries.
        analyze_text = self._is_text_like(path, sample)
        if analyze_text:
            for label, pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(sample):
                    behaviors.add(label)
                    evidence.append(label)
                    score += 2

        clamav = clamav_hits.get(path)
        if clamav:
            behaviors.add("malware_signature")
            evidence.append(f"ClamAV: {clamav}")
            score += 10

        # Executable permission by itself is not enough to flag a file.
        # A signature or suspicious behavioral rule must raise the score.
        if score == 0:
            return None

        try:
            sha256 = self._hash_file(path)
        except (OSError, PermissionError):
            return None

        return HostFinding(path, sha256, frozenset(behaviors), score, tuple(evidence), clamav)

    @staticmethod
    def _is_text_like(path: Path, sample: bytes) -> bool:
        if path.suffix.lower() in TEXT_EXTENSIONS:
            return True
        if not sample:
            return False
        if b"\x00" in sample:
            return False
        printable = sum(byte in b"\t\n\r\f\b" or 32 <= byte < 127 for byte in sample)
        return (printable / len(sample)) >= TEXT_LIKELIHOOD_MIN

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _clamav(self, target: Path) -> dict[Path, str]:
        """Return ClamAV detections keyed by path, using one bounded scan."""
        if not self.clamscan:
            return {}
        try:
            result = subprocess.run(
                [self.clamscan, "--infected", "--no-summary", "--recursive", "--", str(target)],
                capture_output=True,
                text=True,
                timeout=CLAMAV_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {}

        if result.returncode != 1:
            return {}

        hits: dict[Path, str] = {}
        for line in result.stdout.splitlines():
            if not line.endswith(" FOUND"):
                continue
            path_text, _, threat = line.rpartition(": ")
            if not path_text or not threat:
                continue
            hits[Path(path_text).resolve()] = threat.removesuffix(" FOUND")
        return hits
