"""Command-line entry point for BIOAEGIS."""

from __future__ import annotations

import argparse

from . import __version__
from .audit import Auditor
from .host_engine import HostEngine
from .redteam import run as redteam_run
from .tui import run


def _scan_command(target: str, quarantine: bool, deep: bool) -> int:
    engine = HostEngine(deep=deep)
    print(f"BIOAEGIS scan: {target}")
    print(f"Quarantine: {'ENABLED' if quarantine else 'DISABLED (detection only)'}")
    print(f"Scan depth: {'DEEP (full hashes + ClamAV)' if deep else 'NORMAL (bounded static analysis)'}")
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
        print(f"[{result.finding.score:02d}] {result.finding.path}")
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

    for item in report.host:
        print(f"  FILE     [{item.finding.score:02d}] {item.finding.path}")
        print(f"           {'; '.join(item.finding.evidence)}")
    for item in report.runtime:
        print(f"  PROCESS  [{item.score:02d}] PID {item.pid}: {item.command_line}")
        print(f"           {'; '.join(sorted(item.signals))}")
    for item in report.persistence:
        print(f"  PERSIST  [{item.score:02d}] {item.path}")
        print(f"           {'; '.join(item.evidence)}")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bioaegis",
        description="BIOAEGIS biological-inspired defensive system",
    )
    parser.add_argument("--version", action="version", version=f"BIOAEGIS {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a file or directory")
    scan.add_argument("target", help="File or directory to scan")
    scan.add_argument(
        "--quarantine",
        action="store_true",
        help="Actually isolate validated findings into the user-local quarantine",
    )
    scan.add_argument(
        "--deep",
        action="store_true",
        help="Full-hash findings and run recursive ClamAV",
    )

    audit = subparsers.add_parser("audit", help="Read-only file, process, and persistence audit")
    audit.add_argument("target", help="File or directory to scan")
    audit.add_argument("--deep", action="store_true", help="Enable deep file scanning and ClamAV")

    subparsers.add_parser("redteam", help="Run safe local red-team detection and memory tests")

    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(_scan_command(args.target, args.quarantine, args.deep))
    if args.command == "audit":
        raise SystemExit(_audit_command(args.target, args.deep))
    if args.command == "redteam":
        raise SystemExit(redteam_run())

    run()


if __name__ == "__main__":
    main()
