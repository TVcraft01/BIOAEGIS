"""Continuous Linux endpoint protection orchestrator for BIOAEGIS."""

from __future__ import annotations

import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from .host_engine import HostEngine
from .network_scanner import NetworkScanner
from .persistence_scanner import PersistenceScanner
from .realtime import InotifyMonitor
from .runtime_scanner import RuntimeScanner
from .status import write_status

DEFAULT_EVENT_TIMEOUT = 0.35
DEFAULT_SWEEP_INTERVAL = 60.0
DEFAULT_TELEMETRY_INTERVAL = 5.0


def protected_roots() -> tuple[Path, ...]:
    """Return existing user content directories suitable for real-time watch."""
    home = Path.home()
    candidates: list[Path] = []
    config = home / ".config" / "user-dirs.dirs"
    if config.is_file():
        try:
            for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line.startswith("XDG_") or "=" not in line:
                    continue
                _, value = line.split("=", 1)
                value = value.strip().strip('"')
                if value.startswith("$HOME"):
                    value = str(home) + value.removeprefix("$HOME")
                path = Path(os.path.expandvars(value)).expanduser()
                if path.is_dir():
                    candidates.append(path.resolve())
        except OSError:
            pass

    for name in ("Downloads", "Desktop", "Documents"):
        path = home / name
        if path.is_dir():
            candidates.append(path.resolve())

    unique: dict[Path, None] = {}
    for path in candidates:
        unique[path] = None
    return tuple(unique)


class ProtectionService:
    """Event-driven protection plus periodic safety sweeps and telemetry."""

    def __init__(
        self,
        roots: tuple[Path, ...] | None = None,
        sweep_interval: float = DEFAULT_SWEEP_INTERVAL,
        telemetry_interval: float = DEFAULT_TELEMETRY_INTERVAL,
        deep: bool = False,
    ) -> None:
        self.roots = roots or protected_roots()
        if not self.roots:
            raise ValueError("No protected user directories exist")
        if sweep_interval <= 0 or telemetry_interval <= 0:
            raise ValueError("protection intervals must be greater than zero")
        self.sweep_interval = sweep_interval
        self.telemetry_interval = telemetry_interval
        self.engine = HostEngine(deep=deep)
        self.runtime = RuntimeScanner()
        self.persistence = PersistenceScanner()
        self.network = NetworkScanner()
        self._stop = False
        self._last_sweep = 0.0
        self._last_telemetry = 0.0
        self._last_events = 0
        self._findings = 0
        self._quarantined = 0
        self._last_error: str | None = None

    def stop(self, *_args: object) -> None:
        self._stop = True

    def _state(self, running: bool, last_event: str | None = None, **extra: object) -> None:
        write_status(
            {
                "status": "protected" if running else "stopped",
                "running": running,
                "pid": os.getpid(),
                "roots": [str(root) for root in self.roots],
                "findings": self._findings,
                "quarantined": self._quarantined,
                "last_error": self._last_error,
                "last_event": last_event,
                "last_sweep": datetime.fromtimestamp(self._last_sweep, timezone.utc).isoformat() if self._last_sweep else None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                **extra,
            }
        )

    @staticmethod
    def _is_under(path: Path, roots: tuple[Path, ...]) -> bool:
        resolved = path.resolve()
        return any(resolved == root or root in resolved.parents for root in roots)

    def _scan_event(self, path: Path) -> None:
        if not path.exists() or path.is_dir() or path.is_symlink():
            return
        if not self._is_under(path, self.roots):
            return
        for result in self.engine.scan(str(path), quarantine=True, automatic=True):
            self._findings += 1
            if result.quarantined:
                self._quarantined += 1
            self._last_events += 1
            self._state(True, str(path), last_action=result.message, confidence=result.confidence_level)

    def _telemetry_cycle(self) -> None:
        for item in self.runtime.scan():
            if item.score >= 4:
                executable = Path(item.executable)
                if executable.is_file() and self._is_under(executable, self.roots):
                    for result in self.engine.scan(str(executable), quarantine=True, automatic=True):
                        self._findings += 1
                        if result.quarantined:
                            self._quarantined += 1
        # Persistence and listener scanners remain observation-only. Their
        # findings are included in health telemetry without autonomous action.
        self.persistence.scan()
        self.network.scan()

    def _sweep(self) -> None:
        for root in self.roots:
            for result in self.engine.scan(str(root), quarantine=True, automatic=True):
                self._findings += 1
                if result.quarantined:
                    self._quarantined += 1
        self._last_sweep = time.time()

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        monitors = []
        self._state(True)
        try:
            for root in self.roots:
                monitors.append(InotifyMonitor(root))

            while not self._stop:
                now = time.monotonic()
                for monitor in monitors:
                    for path in monitor.poll(DEFAULT_EVENT_TIMEOUT):
                        try:
                            self._scan_event(path)
                        except (OSError, ValueError) as exc:
                            self._last_error = str(exc)
                            self._state(True, str(path))
                    if monitor.overflowed:
                        self._sweep()

                if now - self._last_telemetry >= self.telemetry_interval:
                    try:
                        self._telemetry_cycle()
                    except (OSError, ValueError) as exc:
                        self._last_error = str(exc)
                    self._last_telemetry = now

                if now - self._last_sweep >= self.sweep_interval:
                    try:
                        self._sweep()
                    except (OSError, ValueError) as exc:
                        self._last_error = str(exc)
                    self._state(True)

            return 0
        finally:
            for monitor in monitors:
                monitor.close()
            self._state(False)


def run_protection(**kwargs: object) -> int:
    return ProtectionService(**kwargs).run()
