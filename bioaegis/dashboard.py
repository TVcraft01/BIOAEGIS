"""Local BIOAEGIS security dashboard server."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .host_engine import HostEngine
from .memory import ImmuneMemory
from .quarantine import Quarantine

ASSETS = Path(__file__).with_name("dashboard_static")
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}


def _json_default(value: object) -> object:
    if hasattr(value, "__dict__"):
        return value.__dict__
    if hasattr(value, "_asdict"):
        return value._asdict()  # type: ignore[attr-defined]
    raise TypeError(type(value).__name__)


class _Handler(BaseHTTPRequestHandler):
    server_version = "BIOAEGIS-Dashboard/2.0"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload, default=_json_default).encode("utf-8"), "application/json; charset=utf-8")

    def _asset(self, relative: str) -> None:
        target = (ASSETS / relative).resolve()
        root = ASSETS.resolve()
        if root not in target.parents and target != root:
            self._json(404, {"error": "not found"})
            return
        if not target.is_file():
            self._json(404, {"error": "not found"})
            return
        self._send(200, target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            return self._asset("index.html")
        if path.startswith("/dashboard/"):
            return self._asset(path.removeprefix("/dashboard/"))
        if path == "/api/health":
            return self._json(200, {"status": "ready", "version": __version__, "local": True})
        if path == "/api/memory":
            memory = ImmuneMemory()
            memory.load()
            return self._json(200, {"count": len(memory.entries), "entries": [
                {"name": e.name, "trigger": sorted(e.trigger), "actions": list(e.actions), "rationale": e.rationale}
                for e in memory.entries
            ]})
        if path == "/api/quarantine":
            records = Quarantine().list()
            return self._json(200, {"count": len(records), "records": [
                {"original_path": r.original_path, "quarantine_path": r.quarantine_path, "sha256": r.sha256, "restored_at": r.restored_at}
                for r in records
            ]})
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/scan":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            return self._json(413, {"error": "request too large"})
        raw = self.rfile.read(length).decode("utf-8", errors="strict")
        form = parse_qs(raw, strict_parsing=False)
        target = form.get("target", [""])[0]
        deep = form.get("deep", ["0"])[0] == "1"
        quarantine = form.get("quarantine", ["0"])[0] == "1"
        if not target or len(target) > 4096:
            return self._json(400, {"error": "invalid target"})
        try:
            results = HostEngine(deep=deep).scan(target, quarantine=quarantine)
        except (OSError, ValueError) as exc:
            return self._json(400, {"error": str(exc)})
        payload = []
        for result in results:
            finding = result.finding
            payload.append({"score": finding.score, "path": finding.path, "behaviors": sorted(finding.behaviors), "message": result.message})
        self._json(200, {"results": payload})

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the local dashboard, loopback-only by default."""
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"BIOAEGIS dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
