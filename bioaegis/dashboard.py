"""Local BIOAEGIS security dashboard."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__
from .memory import ImmuneMemory
from .quarantine import Quarantine


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BIOAEGIS // Security Console</title>
<style>
:root{--bg:#070a0f;--panel:#0d121a;--line:#202b39;--text:#e8eef6;--muted:#7e8da0;--cyan:#58d7ff;--green:#57e08b;--amber:#ffc857;--red:#ff647c;--shadow:0 20px 60px rgba(0,0,0,.28)}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#101a27 0,#070a0f 46%);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.shell{display:grid;grid-template-columns:250px 1fr;min-height:100vh}.side{border-right:1px solid var(--line);background:rgba(7,10,15,.82);padding:24px;position:sticky;top:0;height:100vh}.brand{font-weight:800;letter-spacing:.22em;font-size:18px}.brand span{color:var(--cyan)}.tag{color:var(--muted);font-size:11px;margin-top:4px}.nav{margin-top:42px;display:grid;gap:7px}.nav div{padding:11px 12px;border-radius:10px;color:#aeb9c8}.nav .active{background:#111c29;color:#fff;border:1px solid #213347}.side .foot{position:absolute;bottom:22px;color:var(--muted);font-size:11px}.main{padding:28px 34px 38px;max-width:1600px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:.16em;text-transform:uppercase}.title{font-size:30px;font-weight:760;margin:5px 0}.sub{color:var(--muted)}.live{display:flex;align-items:center;gap:9px;color:#b8c5d5}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(87,224,139,.7)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card,.panel{background:linear-gradient(180deg,rgba(17,24,35,.92),rgba(10,14,21,.92));border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}.card{padding:18px}.metric{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}.value{font-size:30px;font-weight:760;margin:6px 0 2px}.hint{color:var(--muted);font-size:12px}.green{color:var(--green)}.cyan{color:var(--cyan)}.amber{color:var(--amber)}.cols{display:grid;grid-template-columns:1.7fr 1fr;gap:14px;margin-top:14px}.panel{padding:19px}.panel h2{font-size:14px;margin:0 0 14px}.panelhead{display:flex;justify-content:space-between;align-items:center}.small{font-size:11px;color:var(--muted)}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:11px 8px;text-align:left;border-bottom:1px solid #18222f}.table th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em}.badge{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:10px;border:1px solid currentColor}.empty{padding:25px;color:var(--muted);text-align:center;border:1px dashed #263343;border-radius:12px}.events{display:grid;gap:9px}.event{display:grid;grid-template-columns:95px 1fr auto;gap:10px;padding:11px 12px;background:#0a1017;border:1px solid #18222f;border-radius:10px}.event .kind{text-transform:uppercase;font-size:10px;letter-spacing:.1em;color:var(--cyan)}.bar{height:7px;background:#18212d;border-radius:99px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--green))}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{background:#132030;color:#dce8f3;border:1px solid #26384b;border-radius:10px;padding:9px 12px;cursor:pointer}.btn:hover{border-color:#45647f;background:#172638}.btn.primary{background:#123042;border-color:#205873;color:#bfefff}.footer{margin-top:16px;color:var(--muted);font-size:11px;text-align:right}@media(max-width:1050px){.shell{grid-template-columns:1fr}.side{display:none}.grid{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}}@media(max-width:620px){.main{padding:18px}.grid{grid-template-columns:1fr}.top{display:block}.live{margin-top:12px}}
</style></head>
<body><div class="shell"><aside class="side"><div class="brand">BIO<span>AEGIS</span></div><div class="tag">DEFENSIVE SECURITY CONSOLE</div><div class="nav"><div class="active">Overview</div><div>Detection</div><div>Immune Memory</div><div>Quarantine</div><div>Telemetry</div></div><div class="foot">Local-only dashboard<br>v{{VERSION}}</div></aside>
<main class="main"><section class="top"><div><div class="eyebrow">System overview</div><div class="title">Security status</div><div class="sub">Evidence-first defense with reversible containment.</div></div><div class="live"><span class="dot"></span>LOCAL ENGINE ONLINE</div></section>
<section class="grid"><div class="card"><div class="metric">Engine</div><div class="value green">READY</div><div class="hint">Read-only analysis path</div></div><div class="card"><div class="metric">Immune rules</div><div class="value cyan" id="memory">—</div><div class="hint">Validated countermeasures</div></div><div class="card"><div class="metric">Quarantined</div><div class="value amber" id="quarantine">—</div><div class="hint">Reversible isolation records</div></div><div class="card"><div class="metric">Protection mode</div><div class="value">DEFENSE</div><div class="hint">No arbitrary execution</div></div></section>
<div class="cols"><section class="panel"><div class="panelhead"><h2>Recent quarantine activity</h2><span class="small" id="updated">updating…</span></div><div id="qtable"></div></section><section class="panel"><div class="panelhead"><h2>Engine safeguards</h2><span class="badge green">ACTIVE</span></div><div class="events"><div class="event"><div class="kind">SCANNER</div><div>Static inspection only</div><div class="green">ON</div></div><div class="event"><div class="kind">VALIDATOR</div><div>Allow-listed responses</div><div class="green">ON</div></div><div class="event"><div class="kind">QUARANTINE</div><div>Hash-verified recovery</div><div class="green">ON</div></div><div class="event"><div class="kind">MEMORY</div><div>Specificity-aware matching</div><div class="green">ON</div></div></div><div style="margin-top:16px"><div class="small" style="margin-bottom:6px">Research maturity</div><div class="bar"><div class="fill" style="width:66%"></div></div><div class="small" style="margin-top:6px">Research prototype — not production EDR/AV.</div></div></section></div>
<div class="cols"><section class="panel"><div class="panelhead"><h2>Operator actions</h2><span class="small">Safe local controls</span></div><div class="actions"><button class="btn primary" onclick="loadData()">Refresh data</button><button class="btn" onclick="window.open('/api/health','_blank')">Open health API</button><button class="btn" onclick="window.open('/api/memory','_blank')">Inspect memory API</button></div></section><section class="panel"><h2>Detection lifecycle</h2><div class="events"><div class="event"><div class="kind">DETECT</div><div>General scanner observes evidence</div><div>→</div></div><div class="event"><div class="kind">INVESTIGATE</div><div>Disposable specialist forms proposal</div><div>→</div></div><div class="event"><div class="kind">VALIDATE</div><div>Independent validator checks response</div><div>→</div></div><div class="event"><div class="kind">REMEMBER</div><div>Validated defense enters immune memory</div><div>✓</div></div></div></section></div>
<div class="footer">BIOAEGIS {{VERSION}} · local dashboard · evidence before action</div></main></div>
<script>const esc=s=>String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));async function loadData(){try{const [m,q]=await Promise.all([fetch('/api/memory'),fetch('/api/quarantine')]);const memory=await m.json(),quarantine=await q.json();document.getElementById('memory').textContent=memory.count;document.getElementById('quarantine').textContent=quarantine.count;document.getElementById('updated').textContent='updated '+new Date().toLocaleTimeString();const rows=quarantine.records.slice(0,8);document.getElementById('qtable').innerHTML=rows.length?`<table class="table"><thead><tr><th>Status</th><th>Artifact</th><th>SHA-256</th></tr></thead><tbody>${rows.map(r=>`<tr><td><span class="badge ${r.restored_at?'cyan':'amber'}">${r.restored_at?'RESTORED':'ISOLATED'}</span></td><td title="${esc(r.original_path)}">${esc(r.original_path.split('/').pop())}</td><td><code>${esc(r.sha256.slice(0,18))}…</code></td></tr>`).join('')}</tbody></table>`:'<div class="empty">No quarantine records. System is clear from the local quarantine index.</div>'}catch(e){document.getElementById('updated').textContent='API unavailable';}}loadData();setInterval(loadData,5000);</script></body></html>'''


class _Handler(BaseHTTPRequestHandler):
    server_version = "BIOAEGIS-Dashboard/1.0"

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, DASHBOARD_HTML.replace("{{VERSION}}", __version__))
        elif path == "/api/health":
            self._send(200, json.dumps({"status":"ready","version":__version__,"local":True}), "application/json")
        elif path == "/api/memory":
            memory = ImmuneMemory()
            entries = getattr(memory, "_entries", [])
            self._send(200, json.dumps({"count":len(entries),"entries":entries}, default=str), "application/json")
        elif path == "/api/quarantine":
            records = Quarantine().list()
            payload=[{"original_path":r.original_path,"quarantine_path":r.quarantine_path,"sha256":r.sha256,"restored_at":r.restored_at} for r in records]
            self._send(200, json.dumps({"count":len(payload),"records":payload}), "application/json")
        else:
            self._send(404, json.dumps({"error":"not found"}), "application/json")

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the dashboard on loopback only by default."""
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"BIOAEGIS dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
