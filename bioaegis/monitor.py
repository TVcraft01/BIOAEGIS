"""Polling monitor for controlled defensive testing."""

from __future__ import annotations

import time
from pathlib import Path

from .host_engine import HostEngine
from .network_scanner import NetworkScanner
from .persistence_scanner import PersistenceScanner
from .runtime_scanner import RuntimeScanner


class Monitor:
    """Poll telemetry continuously without turning every loop into a full disk scan."""

    def __init__(self, target: str | Path, interval: float = 5.0, deep: bool = False) -> None:
        if interval <= 0:
            raise ValueError("interval must be greater than zero")
        self.target = str(Path(target).expanduser())
        self.interval = interval
        self.deep = deep
        self.engine = HostEngine(deep=deep)
        self.runtime = RuntimeScanner()
        self.persistence = PersistenceScanner()
        self.network = NetworkScanner()

    def run(self, quarantine: bool = False, once: bool = False) -> int:
        seen_files: set[tuple[str, str]] = set()
        seen_runtime: set[tuple[int, tuple[str, ...]]] = set()
        seen_persistence: set[tuple[str, tuple[str, ...]]] = set()
        seen_network: set[tuple[str, str, int]] = set()
        cycle = 0
        file_scan_every = 10 if self.target == str(Path.home()) else 1

        print("BIOAEGIS LIVE MONITOR")
        print(f"Target: {self.target}")
        print(f"Interval: {self.interval:g}s")
        print(f"File scan cadence: every {file_scan_every} cycle(s)")
        print(f"Quarantine: {'ENABLED' if quarantine else 'DISABLED'}")
        print("Press Ctrl+C to stop.")
        print()

        while True:
            try:
                cycle += 1

                # Process, persistence and listener telemetry are cheap enough
                # to inspect every cycle. Full recursive file inspection is
                # throttled for large targets such as the user's home directory.
                if cycle == 1 or cycle % file_scan_every == 0:
                    for result in self.engine.scan(self.target, quarantine=quarantine):
                        key = (str(result.finding.path), result.finding.sha256)
                        if key in seen_files:
                            continue
                        seen_files.add(key)
                        print(f"[FILE] [{result.finding.score:02d}] {result.finding.path}")
                        print(f"       {'; '.join(result.finding.evidence)}")
                        print(f"       {result.message}")

                for item in self.runtime.scan():
                    key = (item.pid, tuple(sorted(item.signals)))
                    if key in seen_runtime:
                        continue
                    seen_runtime.add(key)
                    print(f"[PROC] [{item.score:02d}] PID {item.pid}: {item.command_line}")
                    print(f"       {'; '.join(sorted(item.signals))}")

                for item in self.persistence.scan():
                    key = (str(item.path), tuple(sorted(item.signals)))
                    if key in seen_persistence:
                        continue
                    seen_persistence.add(key)
                    print(f"[PERSIST] [{item.score:02d}] {item.path}")
                    print(f"         {'; '.join(item.evidence)}")

                for item in self.network.scan():
                    key = (item.protocol, item.address, item.port)
                    if key in seen_network:
                        continue
                    seen_network.add(key)
                    print(f"[LISTEN] {item.protocol} {item.address}:{item.port}")

                if once:
                    return 0
                time.sleep(self.interval)
            except KeyboardInterrupt:
                print("\nBIOAEGIS monitor stopped.")
                return 0
            except (OSError, ValueError) as exc:
                print(f"BIOAEGIS monitor error: {exc}")
                return 2
