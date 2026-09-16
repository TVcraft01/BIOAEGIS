"""Safe archive/container inspection without extraction or execution."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import PurePosixPath


ARCHIVE_SUFFIXES = {".zip", ".jar", ".whl", ".apk", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"}


def inspect(path: str) -> list[str]:
    """Return suspicious member names/content markers without extracting archives."""
    findings: list[str] = []
    lower = path.lower()
    try:
        if lower.endswith(".zip") or lower.endswith(".jar") or lower.endswith(".whl") or lower.endswith(".apk"):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    member = PurePosixPath(info.filename)
                    if member.is_absolute() or ".." in member.parts:
                        findings.append("archive-path-traversal")
                    if info.file_size > 64 * 1024 * 1024:
                        findings.append("archive-oversized-member")
                    if member.suffix.lower() in {".sh", ".py", ".js", ".ps1", ".bat", ".cmd"}:
                        data = archive.read(info)[:512 * 1024]
                        if b"curl" in data and b"bash" in data:
                            findings.append("archive-download-execute")
        elif lower.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
            with tarfile.open(path, mode="r:*") as archive:
                for member in archive.getmembers():
                    name = PurePosixPath(member.name)
                    if name.is_absolute() or ".." in name.parts:
                        findings.append("archive-path-traversal")
                    if member.issym() or member.islnk():
                        findings.append("archive-link-member")
                    if member.isfile() and member.size > 64 * 1024 * 1024:
                        findings.append("archive-oversized-member")
        return sorted(set(findings))
    except (OSError, ValueError, EOFError, zipfile.BadZipFile, tarfile.TarError):
        return []
