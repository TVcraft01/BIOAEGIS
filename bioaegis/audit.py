"""Unified read-only defensive audit for BIOAEGIS."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .host_engine import HostEngine, HostResult
from .persistence_scanner import PersistenceFinding, PersistenceScanner
from .runtime_scanner import ProcessFinding, RuntimeScanner


@dataclass(frozen=True)
class AuditReport:
    host: tuple[HostResult, ...]
    runtime: tuple[ProcessFinding, ...]
    persistence: tuple[PersistenceFinding, ...]


class Auditor:
    """Combine file, runtime, and persistence inspection without host mutation."""

    def __init__(self, deep: bool = False) -> None:
        self.engine = HostEngine(deep=deep)
        self.runtime = RuntimeScanner()
        self.persistence = PersistenceScanner()

    def run(self, target: str | Path) -> AuditReport:
        host = tuple(self.engine.scan(str(target), quarantine=False))
        runtime = tuple(self.runtime.scan())
        persistence = tuple(self.persistence.scan())
        return AuditReport(host, runtime, persistence)
