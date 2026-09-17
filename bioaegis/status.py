"""Persistent local health state shared by the protection service and dashboard."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def state_root() -> Path:
    root = Path(os.environ.get("BIOAEGIS_STATE_DIR", Path.home() / ".local" / "share" / "bioaegis" / "state"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def status_path() -> Path:
    return state_root() / "status.json"


def write_status(payload: dict[str, Any]) -> None:
    target = status_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = dict(payload)
    data.setdefault("updated_at", datetime.now(timezone.utc).isoformat())
    fd, temporary = tempfile.mkstemp(prefix="status.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, target)
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass


def read_status() -> dict[str, Any]:
    try:
        return json.loads(status_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"running": False, "status": "unknown"}
