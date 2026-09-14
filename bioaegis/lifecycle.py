"""BIOAEGIS lifecycle orchestration.

General A stays conceptually active while a fresh General B is prepared from
validated immune memory. The specialist is disposable and never persisted.
"""

from .general_scanner import GeneralScanner
from .memory import ImmuneMemory
from .models import Threat, ValidationResult
from .specialist import Specialist
from .validator import Validator


class BioAegis:
    def __init__(self, memory: ImmuneMemory | None = None) -> None:
        self.memory = memory or ImmuneMemory()
        self.memory.load()
        self.validator = Validator()
        self.general = GeneralScanner(self.memory)

    def handle(self, threat: Threat) -> ValidationResult | None:
        if self.general.scan(threat) != "UNKNOWN_THREAT":
            return None

        # Specialist lifetime ends when this method finishes.
        specialist = Specialist()
        report = specialist.investigate(threat)
        result = self.validator.validate(threat, report.candidate)

        if result.accepted and report.candidate is not None:
            self.memory.remember(report.candidate)
            self.memory.save()
            # Hot-swap: construct a fresh general scanner from the updated memory.
            self.general = GeneralScanner(self.memory)

        del specialist
        return result
