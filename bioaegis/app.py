"""Desktop launcher for the BIOAEGIS local security console."""

from __future__ import annotations

import threading
import time
import webbrowser

from .dashboard import serve


def _start_browser_fallback(url: str, thread: threading.Thread) -> None:
    """Open the local console in the default browser and keep the server alive."""
    print(f"BIOAEGIS native window unavailable; opening browser: {url}")
    webbrowser.open(url)
    thread.join()


def launch(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Launch BIOAEGIS as a desktop-style local web application.

    pywebview provides a native window when a supported GUI backend is available.
    If pywebview or its native backend is unavailable, the local console opens in
    the system browser instead of terminating with a traceback.
    """
    thread = threading.Thread(target=serve, kwargs={"host": host, "port": port}, daemon=True)
    thread.start()
    url = f"http://{host}:{port}"
    time.sleep(0.15)

    try:
        import webview  # type: ignore
        from webview.errors import WebViewException  # type: ignore
    except ImportError:
        _start_browser_fallback(url, thread)
        return

    try:
        webview.create_window(
            "BIOAEGIS Security Console",
            url,
            width=1440,
            height=920,
            min_size=(1100, 700),
        )
        webview.start()
    except WebViewException:
        _start_browser_fallback(url, thread)


if __name__ == "__main__":
    launch()
