"""Deterministic confidence scoring and evidence fusion."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfidenceResult:
    score: int
    level: str
    reasons: tuple[str, ...]


WEIGHTS = {
    "malware_signature": 60,
    "eicar-test-signature": 60,
    "download-and-execute": 18,
    "download-eval": 18,
    "reverse-shell": 20,
    "destructive-command": 24,
    "base64-payload": 10,
    "hidden_executable": 8,
    "executable": 4,
}


def fuse(behaviors: set[str] | frozenset[str], external_hits: int = 0) -> ConfidenceResult:
    score = min(100, sum(WEIGHTS.get(item, 0) for item in behaviors) + min(20, external_hits * 10))
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
