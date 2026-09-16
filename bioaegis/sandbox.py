"""Non-executing analysis sandbox workspace."""

from __future__ import annotations

import json
from pathlib import Path


class AnalysisSandbox:
    """Create an isolated workspace and metadata manifest without executing samples."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def create(self, sample: str | Path) -> Path:
        sample_path = Path(sample).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps({"sample": str(sample_path), "execution": "disabled", "network": "disabled"}, indent=2) + "\n",
            encoding="utf-8",
        )
        return manifest
