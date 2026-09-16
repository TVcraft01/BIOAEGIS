"""Desktop launcher for the BIOAEGIS local security console."""

from __future__ import annotations

import threading
import time
import webbrowser

from .dashboard import serve


def launch(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Launch BIOAEGIS as a desktop-style local web application.

    If pywebview is installed, the console is placed in a native window.
    Otherwise the system browser is opened automatically.
    """
    thread = threading.Thread(target=serve, kwargs={"host": host, "port": port}, daemon=True)
    thread.start()
    url = f"http://{host}:{port}"
    time.sleep(0.15)
    try:
        import webview  # type: ignore
    except ImportError:
        webbrowser.open(url)
        thread.join()
        return
    webview.create_window("BIOAEGIS Security Console", url, width=1440, height=920, min_size=(1100, 700))
    webview.start()
