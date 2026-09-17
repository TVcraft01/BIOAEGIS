"""Desktop launcher for the BIOAEGIS local security console."""

from __future__ import annotations

import os
import platform
import threading
import time
import urllib.error
import urllib.request
import webbrowser

from .dashboard import serve


def _dashboard_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=0.35) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return False


def _start_dashboard(host: str, port: int) -> tuple[str, threading.Thread | None]:
    url = f"http://{host}:{port}"
    if _dashboard_ready(url):
        return url, None

    thread = threading.Thread(target=serve, kwargs={"host": host, "port": port}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if _dashboard_ready(url):
            return url, thread
        time.sleep(0.05)

    return url, thread


def _start_browser_fallback(url: str, thread: threading.Thread | None, reason: str | None = None) -> None:
    """Open the local console in the default browser and keep a new server alive."""
    if reason:
        print(f"BIOAEGIS native window unavailable ({reason}); opening browser: {url}")
    else:
        print(f"BIOAEGIS native window unavailable; opening browser: {url}")
    webbrowser.open(url)
    if thread is not None:
        thread.join()


def _configure_linux_qt() -> None:
    """Choose a predictable Qt platform and conservative WebEngine flags."""
    if not os.environ.get("QT_QPA_PLATFORM"):
        if os.environ.get("WAYLAND_DISPLAY"):
            os.environ["QT_QPA_PLATFORM"] = "wayland"
        elif os.environ.get("DISPLAY"):
            os.environ["QT_QPA_PLATFORM"] = "xcb"
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")


def _launch_qt(url: str, thread: threading.Thread | None) -> None:
    """Run the Linux desktop console directly with PySide6 QtWebEngine."""
    _configure_linux_qt()
    try:
        from PySide6.QtCore import QUrl
        from PySide6.QtWidgets import QApplication
        from PySide6.QtWebEngineWidgets import QWebEngineView
    except ImportError as exc:
        _start_browser_fallback(url, thread, f"QtWebEngine import failed: {exc}")
        return

    try:
        app = QApplication.instance() or QApplication([])
        window = QWebEngineView()
        window.setWindowTitle("BIOAEGIS Security Console")
        window.resize(1440, 920)
        window.setMinimumSize(1100, 700)
        window.setUrl(QUrl(url))
        window.show()
        window.raise_()
        window.activateWindow()

        print(
            "BIOAEGIS native Qt console started "
            f"(platform={os.environ.get('QT_QPA_PLATFORM', 'auto')})."
        )
        started = time.monotonic()
        exit_code = app.exec()
        runtime = time.monotonic() - started

        if runtime < 0.75:
            _start_browser_fallback(
                url,
                thread,
                f"Qt event loop exited immediately (code {exit_code})",
            )
    except Exception as exc:  # noqa: BLE001
        _start_browser_fallback(url, thread, f"QtWebEngine startup failed: {exc}")


def _launch_pywebview(url: str, thread: threading.Thread | None) -> None:
    """Run the desktop console through pywebview on non-Linux platforms."""
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
    except WebViewException as exc:
        _start_browser_fallback(url, thread, str(exc))


def launch(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Launch BIOAEGIS without creating duplicate local dashboard servers."""
    url, thread = _start_dashboard(host, port)

    if platform.system() == "Linux":
        _launch_qt(url, thread)
        return

    _launch_pywebview(url, thread)


if __name__ == "__main__":
    launch()
