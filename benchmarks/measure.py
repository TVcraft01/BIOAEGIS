"""Reproducible local benchmark harness for BIOAEGIS scanning.

The harness measures scanner wall time and finding counts over a user-supplied
benign corpus. It never executes corpus files. Published detection or false-
positive claims require an independently curated corpus and methodology.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from pathlib import Path

from bioaegis.host_scanner import HostScanner


def collect_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return sorted(files)


def run_once(paths: list[Path], deep: bool) -> tuple[float, int]:
    scanner = HostScanner(deep=deep)
    started = time.perf_counter()
    findings = 0
    for path in paths:
        findings += len(scanner.scan(path))
    return time.perf_counter() - started, findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark BIOAEGIS read-only scanning")
    parser.add_argument("corpus", type=Path, help="Directory containing benign or evaluation files")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")
    root = args.corpus.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"corpus is not a directory: {root}")

    paths = collect_files(root)
    if not paths:
        raise SystemExit("corpus contains no regular files")

    runs = [run_once(paths, args.deep) for _ in range(args.repeat)]
    elapsed = [item[0] for item in runs]
    findings = [item[1] for item in runs]
    total_bytes = sum(path.stat().st_size for path in paths)

    result = {
        "corpus": str(root),
        "files": len(paths),
        "bytes": total_bytes,
        "deep": args.deep,
        "repeat": args.repeat,
        "elapsed_seconds": runs[-1][0],
        "median_elapsed_seconds": statistics.median(elapsed),
        "files_per_second": len(paths) / statistics.median(elapsed),
        "mib_per_second": (total_bytes / (1024 * 1024)) / statistics.median(elapsed),
        "findings_per_run": findings,
        "python_pid": os.getpid(),
    }

    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
