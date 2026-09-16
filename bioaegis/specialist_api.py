"""Safe plug-in contract for deterministic or local specialist implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .host_scanner import HostFinding
from .models import SpecialistReport


class SpecialistProvider(ABC):
    """A specialist may analyze evidence, but cannot directly execute actions."""

    @abstractmethod
    def investigate(self, finding: HostFinding) -> SpecialistReport:
        raise NotImplementedError


class DeterministicSpecialistProvider(SpecialistProvider):
    """Adapter for the built-in deterministic specialist."""

    def __init__(self) -> None:
        from .host_specialist import HostSpecialist

        self._specialist = HostSpecialist()

    def investigate(self, finding: HostFinding) -> SpecialistReport:
        return self._specialist.investigate(finding)
