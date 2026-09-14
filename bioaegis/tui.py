"""Terminal interface for the safe BIOAEGIS prototype."""

from __future__ import annotations

import curses

from . import __version__
from .lifecycle import BioAegis
from .models import Threat


def _safe_addstr(stdscr, y: int, x: int, text: str, attr: int = 0) -> None:
    """Write text without crashing when the terminal is too small."""
    height, width = stdscr.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    available = max(0, width - x - 1)
    try:
        stdscr.addnstr(y, x, text, available, attr)
    except curses.error:
        pass


def _draw_box(stdscr, top: int, left: int, bottom: int, right: int) -> None:
    """Draw a simple ASCII box that works in most terminals."""
    width = right - left
    if width < 2 or bottom <= top:
        return
    _safe_addstr(stdscr, top, left, "+" + "-" * (width - 1) + "+")
    for y in range(top + 1, bottom):
        _safe_addstr(stdscr, y, left, "|")
        _safe_addstr(stdscr, y, right, "|")
    _safe_addstr(stdscr, bottom, left, "+" + "-" * (width - 1) + "+")


def run() -> None:
    """Launch the BIOAEGIS terminal interface."""
    curses.wrapper(_main)


def _main(stdscr) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)

    engine = BioAegis()
    message = "READY — simulation mode only"

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        if height < 20 or width < 64:
            _safe_addstr(stdscr, 1, 2, "BIOAEGIS needs at least 64x20 terminal size.")
            _safe_addstr(stdscr, 2, 2, f"Current: {width}x{height}")
            _safe_addstr(stdscr, 4, 2, "Resize the terminal, then press any key.")
            stdscr.refresh()
            stdscr.getch()
            continue

        title = f" BIOAEGIS  //  DIGITAL IMMUNE SYSTEM  //  v{__version__} "
        _safe_addstr(stdscr, 1, 2, title, curses.A_BOLD)
        _draw_box(stdscr, 2, 2, 11, width - 3)
        _safe_addstr(stdscr, 4, 5, "SYSTEM STATUS", curses.A_BOLD)
        _safe_addstr(stdscr, 5, 5, "General Scanner     ACTIVE")
        _safe_addstr(stdscr, 6, 5, f"Immune Memory       {len(engine.memory.entries)} responses")
        _safe_addstr(stdscr, 7, 5, "Specialist          DISPOSABLE / STANDBY")
        _safe_addstr(stdscr, 8, 5, "Validator           ACTIVE")
        _safe_addstr(stdscr, 9, 5, "Host protection     SIMULATION ONLY")

        _draw_box(stdscr, 13, 2, 19, width - 3)
        _safe_addstr(stdscr, 14, 5, "CONTROLS", curses.A_BOLD)
        _safe_addstr(stdscr, 15, 5, "[S] Simulated scan     [M] Immune memory     [Q] Quit")
        _safe_addstr(stdscr, 17, 5, "STATUS: " + message)
        _safe_addstr(stdscr, height - 2, 2, "BIOAEGIS v0.1 — no real files, malware, or host commands are executed.")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q"), 27):
            return
        if key in (ord("s"), ord("S")):
            threat = Threat(
                threat_id="demo-001",
                family="demo",
                behavior={"persistence", "resource_abuse"},
                resource="simulated-resource",
                variant="demo",
            )
            result = engine.handle(threat)
            if result is None:
                message = "KNOWN THREAT — immune response reused"
            elif result.accepted:
                message = "NEW THREAT — specialist response validated and remembered"
            else:
                message = "THREAT RESPONSE REJECTED — escalation required"
        elif key in (ord("m"), ord("M")):
            message = f"IMMUNE MEMORY: {len(engine.memory.entries)} validated response(s)"
