"""Read-only host analysis for BIOAEGIS."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .archive_scanner import ARCHIVE_SUFFIXES, inspect as inspect_archive
from .confidence import fuse

NORMAL_ANALYSIS_BYTES = 512 * 1024
DEEP_ANALYSIS_BYTES = 8 * 1024 * 1024
NORMAL_SNIFF_BYTES = 4 * 1024
TEXT_SAMPLE_BYTES = 256 * 1024
CLAMAV_TIMEOUT_SECONDS = 30
TEXT_LIKELIHOOD_MIN = 0.85
EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

SUSPICIOUS_PATTERNS = (
    ("download-and-execute", re.compile(rb"(?:curl|wget)[^\n]{0,300}(?:\||;)[^\n]{0,100}(?:sh|bash)")),
    ("download-eval", re.compile(rb"(?:eval|source|exec)[ \t\r\n]*(?:[\"']?\$\([ \t\r\n]*)?(?:curl|wget)[^\n]{0,300}\)?")),
    ("script-interpreter-command", re.compile(rb"(?:^|[;&|])[ \t]*(?:python3?|perl|ruby|node|php|bash|sh|zsh)[ \t]+(?:-c|--eval|-e)[ \t]")),
    ("obfuscated-command", re.compile(rb"(?:printf|echo)[^\n]{0,200}(?:base64|\\x[0-9a-f]{2})[^\n]{0,200}(?:bash|sh|python)")),
    ("base64-payload", re.compile(rb"base64[ \t]+(?:-d|--decode)")),
    ("reverse-shell", re.compile(rb"(?:/dev/tcp/|nc[ \t]+[^\n]{0,80}-e[ \t]+(?:/bin/)?(?:sh|bash)|socat[^\n]{0,120}exec)")),
    ("destructive-command", re.compile(rb"(?:rm[ \t]+-rf[ \t]+/|mkfs\.|dd[ \t]+if=/dev/(?:zero|random))")),
    ("suspicious-temp-execution", re.compile(rb"(?:/tmp/|/var/tmp/|/dev/shm/)[^\s]{1,180}[ \t]*(?:;|&&|\||$)")),
    ("suspicious-persistence", re.compile(rb"(?:\.config/autostart/|systemd/user/|\.profile|\.bashrc|crontab)[^\n]{0,180}(?:curl|wget|python|bash|sh)")),
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
    """Read-only scanner. It never executes, deletes, or quarantines files."""

    def __init__(self, max_bytes: int | None = None, deep: bool = False) -> None:
        self.deep = deep
        self.max_bytes = max_bytes if max_bytes is not None else (
            DEEP_ANALYSIS_BYTES if deep else NORMAL_ANALYSIS_BYTES
        )
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
        skip_names = {
            ".cache", ".npm", ".cargo", ".rustup", ".venv", "node_modules",
            "__pycache__", ".gradle", ".m2", ".git",
        }
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [
                d for d in dirs
                if d not in skip_names and not (Path(current) / d).is_symlink()
            ]
            for name in files:
                path = Path(current) / name
                if path.is_symlink() or not path.is_file():
                    continue
                yield path

    def _inspect(self, path: Path, clamav_hits: dict[Path, str]) -> HostFinding | None:
        try:
            stat = path.stat()
        except (OSError, PermissionError):
            return None

        behaviors: set[str] = set()
        evidence: list[str] = []

        if bool(stat.st_mode & 0o111):
            behaviors.add("executable")
            evidence.append("executable permission")
        if path.name.startswith(".") and bool(stat.st_mode & 0o111):
            behaviors.add("hidden_executable")
            evidence.append("hidden executable filename")

        clamav = clamav_hits.get(path.resolve())
        if clamav:
            behaviors.add("malware_signature")
            evidence.append(f"ClamAV: {clamav}")

        if path.suffix.lower() in ARCHIVE_SUFFIXES:
            for marker in inspect_archive(str(path)):
                behaviors.add(marker)
                evidence.append(marker)

        sample = b""
        should_read = self.deep or bool(stat.st_mode & 0o111) or path.suffix.lower() in TEXT_EXTENSIONS
        if not should_read and not self.deep:
            try:
                with path.open("rb") as handle:
                    sniff = handle.read(NORMAL_SNIFF_BYTES)
            except (OSError, PermissionError):
                return None
            if not self._is_text_like(path, sniff):
                return self._finding_if_scored(path, behaviors, evidence, clamav)
            should_read = True

        if should_read:
            try:
                with path.open("rb") as handle:
                    sample = handle.read(self.max_bytes)
            except (OSError, PermissionError):
                return None

            if EICAR_TEST_SIGNATURE in sample:
                behaviors.add("eicar-test-signature")
                evidence.append("EICAR test signature")

            if self._is_text_like(path, sample[:TEXT_SAMPLE_BYTES]):
                for label, pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(sample):
                        behaviors.add(label)
                        evidence.append(label)

        return self._finding_if_scored(path, behaviors, evidence, clamav)

    def _finding_if_scored(
        self,
        path: Path,
        behaviors: set[str],
        evidence: list[str],
        clamav: str | None,
    ) -> HostFinding | None:
        confidence = fuse(behaviors, external_hits=1 if clamav else 0)
        if confidence.score == 0:
            return None
        try:
            sha256 = self._hash_file(path)
        except (OSError, PermissionError):
            return None
        return HostFinding(path, sha256, frozenset(behaviors), confidence.score, tuple(sorted(set(evidence))), clamav)

    @staticmethod
    def _is_text_like(path: Path, sample: bytes) -> bool:
        if path.suffix.lower() in TEXT_EXTENSIONS:
            return True
        if not sample or b"\x00" in sample:
            return False
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            return False
        printable = sum(sample.count(bytes((value,))) for value in range(32, 127))
        allowed = printable + sample.count(b"\t") + sample.count(b"\n") + sample.count(b"\r") + sample.count(b"\f") + sample.count(b"\b")
        return (allowed / len(sample)) >= TEXT_LIKELIHOOD_MIN

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _clamav(self, target: Path) -> dict[Path, str]:
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
