"""Core data models for the BIOAEGIS simulation.

The prototype deliberately models threats instead of touching the host OS.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Threat:
    """Benign representation of a detected threat."""

    threat_id: str
    family: str
    behavior: frozenset[str]
    resource: str
    variant: str = "unknown"


@dataclass(frozen=True)
class Countermeasure:
    """A safe, declarative response to a threat behavior pattern."""

    name: str
    trigger: frozenset[str]
    actions: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    checks: dict[str, bool]
    reason: str


@dataclass
class SpecialistReport:
    threat_id: str
    candidate: Countermeasure | None
    observations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
