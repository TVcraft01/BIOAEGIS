"""Unified read-only defensive audit for BIOAEGIS."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .host_engine import HostEngine, HostResult
from .network_scanner import Listener, NetworkScanner
from .persistence_scanner import PersistenceFinding, PersistenceScanner
from .runtime_scanner import ProcessFinding, RuntimeScanner


@dataclass(frozen=True)
class AuditReport:
    host: tuple[HostResult, ...]
    runtime: tuple[ProcessFinding, ...]
    persistence: tuple[PersistenceFinding, ...]
    network: tuple[Listener, ...]


class Auditor:
    """Combine file, runtime, persistence, and listener inspection without host mutation."""

    def __init__(self, deep: bool = False) -> None:
        self.engine = HostEngine(deep=deep)
        self.runtime = RuntimeScanner()
        self.persistence = PersistenceScanner()
        self.network = NetworkScanner()

    def run(self, target: str | Path) -> AuditReport:
        host = tuple(self.engine.scan(str(target), quarantine=False))
        runtime = tuple(self.runtime.scan())
        persistence = tuple(self.persistence.scan())
        network = tuple(self.network.scan())
        return AuditReport(host, runtime, persistence, network)
