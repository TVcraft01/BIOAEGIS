"""Command-line entry point for BIOAEGIS."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import Auditor
from .dashboard import serve as dashboard_serve
from .host_engine import HostEngine
from .monitor import Monitor
from .protection import run_protection
from .quarantine import Quarantine
from .redteam import run as redteam_run
from .tamper import write_manifest
from .test_runner import run as test_run
from .tui import run


def _scan_command(target: str, quarantine: bool, deep: bool) -> int:
    engine = HostEngine(deep=deep)
    print(f"BIOAEGIS scan: {target}")
    print(f"Quarantine: {'ENABLED' if quarantine else 'DISABLED (detection only)'}")
    print(f"Scan depth: {'DEEP (full hashes + ClamAV)' if deep else 'NORMAL (selective bounded static analysis)'}")
    print()
    try:
        results = engine.scan(target, quarantine=quarantine)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    if not results:
        print("No suspicious findings.")
        return 0
    for result in results:
        print(f"[{result.finding.score:02d}] {result.confidence_level} {result.finding.path}")
        print(f"     SHA-256: {result.finding.sha256}")
        print(f"     Signals: {', '.join(sorted(result.finding.behaviors))}")
        if result.finding.evidence:
            print(f"     Evidence: {'; '.join(result.finding.evidence)}")
        print(f"     Action: {result.message}")
        if result.quarantine_record:
            print(f"     Quarantine: {result.quarantine_record.quarantine_path}")
        print()
    return 0


def _audit_command(target: str, deep: bool) -> int:
    print(f"BIOAEGIS audit: {target}")
    print(f"Mode: {'DEEP' if deep else 'NORMAL'}")
    print()
    try:
        report = Auditor(deep=deep).run(target)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    print(f"FILE FINDINGS       : {len(report.host)}")
    print(f"RUNTIME FINDINGS    : {len(report.runtime)}")
    print(f"PERSISTENCE FINDINGS: {len(report.persistence)}")
    print(f"LISTENERS           : {len(report.network)}")
    for item in report.host:
        print(f"  FILE     [{item.finding.score:02d}] {item.finding.path}")
        print(f"           {'; '.join(item.finding.evidence)}")
    for item in report.runtime:
        print(f"  PROCESS  [{item.score:02d}] PID {item.pid}: {item.command_line}")
        print(f"           {'; '.join(sorted(item.signals))}")
    for item in report.persistence:
        print(f"  PERSIST  [{item.score:02d}] {item.path}")
        print(f"           {'; '.join(item.evidence)}")
    for item in report.network:
        print(f"  LISTEN   {item.protocol} {item.address}:{item.port}")
    return 0


def _monitor_command(target: str, interval: float, quarantine: bool, deep: bool, once: bool) -> int:
    try:
        return Monitor(target, interval=interval, deep=deep).run(quarantine=quarantine, once=once)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2


def _update_command(apply_update: bool) -> int:
    try:
        from .updates import apply_wheel, check_for_update, download_and_verify
    except ImportError:
        print("Signed update verifier is not installed.")
        return 2

    update = check_for_update(__version__)
    if update is None:
        print("BIOAEGIS update channel: no signed update available.")
        return 0

    print(f"BIOAEGIS update available: {__version__} -> {update.version}")
    if not apply_update:
        print("Update not applied. The signed release has passed verification.")
        return 0

    root = Path(os.environ.get("BIOAEGIS_HOME", Path.cwd())).resolve()
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError(f"BIOAEGIS installation root not found: {root}")
    wheel = download_and_verify(update)
    apply_wheel(wheel, root)
    write_manifest(root)
    print(f"BIOAEGIS updated to {update.version}.")
    return 0


def _quarantine_command(action: str, path: str | None) -> int:
    quarantine = Quarantine()
    try:
        records = quarantine.list()
        if action == "list":
            if not records:
                print("BIOAEGIS quarantine: empty")
                return 0
            print("BIOAEGIS quarantine")
            for record in records:
                status = "RESTORED" if record.restored_at is not None else "ISOLATED"
                print(f"[{status}] {record.quarantine_path}")
                print(f"  Original: {record.original_path}")
                print(f"  SHA-256 : {record.sha256}")
            return 0
        if path is None:
            print("ERROR: a quarantine path is required for restore")
            return 2
        record = quarantine.restore(path)
        restored = datetime.fromtimestamp(record.restored_at or 0, tz=timezone.utc).isoformat()
        print("BIOAEGIS quarantine restore")
        print(f"  Restored: {record.original_path}")
        print(f"  SHA-256 : {record.sha256}")
        print(f"  Verified: {restored}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2


def main() -> None:
    parser = argparse.ArgumentParser(prog="bioaegis", description="BIOAEGIS biological-inspired defensive system")
    parser.add_argument("--version", action="version", version=f"BIOAEGIS {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a file or directory")
    scan.add_argument("target")
    scan.add_argument("--quarantine", action="store_true")
    scan.add_argument("--deep", action="store_true")

    audit = subparsers.add_parser("audit", help="Read-only file, process, persistence, and network audit")
    audit.add_argument("target")
    audit.add_argument("--deep", action="store_true")

    monitor = subparsers.add_parser("monitor", help="Continuously poll defensive telemetry")
    monitor.add_argument("target")
    monitor.add_argument("--interval", type=float, default=5.0)
    monitor.add_argument("--quarantine", action="store_true")
    monitor.add_argument("--deep", action="store_true")
    monitor.add_argument("--once", action="store_true")

    protect = subparsers.add_parser("protect", help="Run continuous event-driven endpoint protection")
    protect.add_argument("--sweep-interval", type=float, default=60.0)
    protect.add_argument("--telemetry-interval", type=float, default=5.0)
    protect.add_argument("--deep", action="store_true")

    update = subparsers.add_parser("update", help="Check or apply a signed BIOAEGIS release")
    update.add_argument("--apply", action="store_true", help="Install a verified update")

    dashboard = subparsers.add_parser("dashboard", help="Open the local BIOAEGIS security console")
    dashboard.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only)")
    dashboard.add_argument("--port", type=int, default=8765, help="HTTP port")

    quarantine = subparsers.add_parser("quarantine", help="Inspect or safely restore quarantined files")
    quarantine_subparsers = quarantine.add_subparsers(dest="quarantine_action", required=True)
    quarantine_subparsers.add_parser("list", help="List quarantined files")
    restore = quarantine_subparsers.add_parser("restore", help="Restore one quarantined file")
    restore.add_argument("path")

    subparsers.add_parser("redteam", help="Run safe local red-team detection and memory tests")
    subparsers.add_parser("test", help="Run BIOAEGIS tests with its installed Python environment")

    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(_scan_command(args.target, args.quarantine, args.deep))
    if args.command == "audit":
        raise SystemExit(_audit_command(args.target, args.deep))
    if args.command == "monitor":
        raise SystemExit(_monitor_command(args.target, args.interval, args.quarantine, args.deep, args.once))
    if args.command == "protect":
        raise SystemExit(
            run_protection(
                sweep_interval=args.sweep_interval,
                telemetry_interval=args.telemetry_interval,
                deep=args.deep,
            )
        )
    if args.command == "update":
        raise SystemExit(_update_command(args.apply))
    if args.command == "dashboard":
        dashboard_serve(host=args.host, port=args.port)
        return
    if args.command == "quarantine":
        raise SystemExit(_quarantine_command(args.quarantine_action, getattr(args, "path", None)))
    if args.command == "redteam":
        raise SystemExit(redteam_run())
    if args.command == "test":
        raise SystemExit(test_run())
    run()


if __name__ == "__main__":
    main()
