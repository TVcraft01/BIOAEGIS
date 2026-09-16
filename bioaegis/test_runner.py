"""Run BIOAEGIS's test suite with the installed private interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run() -> int:
    root = Path(__file__).resolve().parent.parent
    tests = root / "tests"
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", str(tests)], cwd=root, check=False)
    return result.returncode
