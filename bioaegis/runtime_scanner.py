"""Read-only Linux runtime inspection for BIOAEGIS."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

RUNTIME_PATTERNS = (
    ("reverse-shell", re.compile(r"(?:/dev/tcp/|\bnc\b[^\n]{0,80}\s-e\s|\bsocat\b[^\n]{0,120}\bexec\b)", re.I)),
    ("download-execute", re.compile(r"(?:curl|wget)[^\n]{0,240}(?:\||;)[^\n]{0,80}(?:sh|bash)\b", re.I)),
    ("encoded-command", re.compile(r"(?:base64\s+(?:-d|--decode)|python\s+-c|perl\s+-e)", re.I)),
    ("suspicious-temp-execution", re.compile(r"(?:/tmp/|/var/tmp/|/dev/shm/)[^\s]+", re.I)),
)


@dataclass(frozen=True)
class ProcessFinding:
    pid: int
    ppid: int | None
    executable: str
    command_line: str
    signals: frozenset[str]
    score: int


class RuntimeScanner:
    """Inspect /proc without executing, stopping, or modifying processes."""

    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def scan(self) -> list[ProcessFinding]:
        if not self.proc_root.is_dir():
            return []
        findings: list[ProcessFinding] = []
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            finding = self._inspect_pid(int(entry.name), entry)
            if finding is not None:
                findings.append(finding)
        return findings

    def _inspect_pid(self, pid: int, proc_dir: Path) -> ProcessFinding | None:
        try:
            raw_cmdline = (proc_dir / "cmdline").read_bytes()
            command_line = raw_cmdline.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            executable = os.readlink(proc_dir / "exe")
            status = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

        signals: set[str] = set()
        score = 0
        for label, pattern in RUNTIME_PATTERNS:
            if pattern.search(command_line):
                signals.add(label)
                score += 2

        if not signals:
            return None

        ppid = None
        match = re.search(r"^PPid:\s*(\d+)", status, re.MULTILINE)
        if match:
            ppid = int(match.group(1))

        return ProcessFinding(pid, ppid, executable, command_line, frozenset(signals), score)
