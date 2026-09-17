"""Desktop launcher for the BIOAEGIS local security console."""

from __future__ import annotations

import platform
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

    Linux uses pywebview's Qt backend explicitly because pywebview can otherwise
    probe GTK first. Other platforms keep their normal backend selection. If
    pywebview or its native backend is unavailable, the local console opens in
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
        gui = "qt" if platform.system() == "Linux" else None
        if gui is None:
            webview.start()
        else:
            webview.start(gui=gui)
    except WebViewException:
        _start_browser_fallback(url, thread)


if __name__ == "__main__":
    launch()
