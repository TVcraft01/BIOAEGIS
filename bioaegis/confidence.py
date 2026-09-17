"""Deterministic confidence scoring and independent evidence fusion."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfidenceResult:
    score: int
    level: str
    reasons: tuple[str, ...]


# Scores are deliberately conservative for automatic containment. A single weak
# indicator should not be enough to quarantine a legitimate file.
WEIGHTS = {
    "malware_signature": 100,
    "eicar-test-signature": 100,
    "download-and-execute": 28,
    "download-eval": 28,
    "reverse-shell": 36,
    "destructive-command": 36,
    "script-interpreter-command": 8,
    "obfuscated-command": 10,
    "suspicious-temp-execution": 14,
    "suspicious-persistence": 18,
    "archive-path-traversal": 42,
    "archive-link-member": 30,
    "archive-oversized-member": 12,
    "archive-download-execute": 35,
    "base64-payload": 10,
    "hidden_executable": 8,
    "executable": 3,
}


def fuse(
    behaviors: set[str] | frozenset[str],
    external_hits: int = 0,
    independent_sources: int = 0,
) -> ConfidenceResult:
    """Fuse static/runtime/external evidence into a bounded confidence score."""
    score = sum(WEIGHTS.get(item, 0) for item in behaviors)
    score += min(20, max(0, external_hits) * 10)
    score += min(20, max(0, independent_sources) * 10)
    score = min(100, score)

    if score >= 80:
        level = "HIGH"
    elif score >= 45:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"

    reasons = tuple(sorted(item for item in behaviors if item in WEIGHTS))
    return ConfidenceResult(score, level, reasons)
