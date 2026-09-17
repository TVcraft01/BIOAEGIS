"""Linux inotify event source for near-real-time BIOAEGIS protection."""

from __future__ import annotations

import ctypes
import os
import select
from pathlib import Path

IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_MOVED_FROM = 0x00000040
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_ATTRIB = 0x00000004
IN_ISDIR = 0x40000000
IN_Q_OVERFLOW = 0x00004000
IN_NONBLOCK = os.O_NONBLOCK


class InotifyMonitor:
    """Read-only event source; analysis and containment remain elsewhere."""

    def __init__(self, target: str | Path) -> None:
        if os.name != "posix":
            raise OSError("inotify monitor requires Linux")
        self.target = Path(target).expanduser().resolve()
        if not self.target.is_dir():
            raise NotADirectoryError(self.target)
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._fd = libc.inotify_init1(IN_NONBLOCK)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._libc = libc
        self._watches: dict[int, Path] = {}
        self._overflowed = False
        self._add_tree(self.target)

    def _add_tree(self, root: Path) -> None:
        for current, dirs, _ in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            self._watch(Path(current))

    def _watch(self, path: Path) -> None:
        if path in self._watches.values():
            return
        mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_ATTRIB
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), mask)
        if wd >= 0:
            self._watches[wd] = path

    def poll(self, timeout: float = 0.5) -> list[Path]:
        self._overflowed = False
        if select.select([self._fd], [], [], timeout)[0] == []:
            return []
        data = os.read(self._fd, 4 * 1024 * 1024)
        events: list[Path] = []
        offset = 0
        record_size = 16
        while offset + record_size <= len(data):
            wd = int.from_bytes(data[offset:offset + 4], "little", signed=True)
            mask = int.from_bytes(data[offset + 4:offset + 8], "little")
            name_len = int.from_bytes(data[offset + 12:offset + 16], "little")
            end = offset + record_size + name_len
            if end > len(data):
                break
            if mask & IN_Q_OVERFLOW:
                self._overflowed = True
            raw = data[offset + 16:end].split(b"\0", 1)[0]
            base = self._watches.get(wd)
            if base is not None:
                path = base / os.fsdecode(raw) if raw else base
                events.append(path)
                if mask & IN_ISDIR and mask & IN_CREATE and path.is_dir():
                    self._add_tree(path)
            offset = end
        return events

    @property
    def overflowed(self) -> bool:
        return self._overflowed

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "InotifyMonitor":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
