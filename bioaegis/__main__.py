"""Command-line entry point for BIOAEGIS."""

from __future__ import annotations

import argparse

from . import __version__
from .host_engine import HostEngine
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
        help="Full-hash findings and run recursive ClamAV (slower; useful for verification)",
    )

    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(_scan_command(args.target, args.quarantine, args.deep))

    run()


if __name__ == "__main__":
    main()
