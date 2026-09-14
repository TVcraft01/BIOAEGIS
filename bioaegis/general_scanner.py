"""General scanner that consumes persistent immune memory."""

from .memory import ImmuneMemory
from .models import Threat


class GeneralScanner:
    def __init__(self, memory: ImmuneMemory) -> None:
        self.memory = memory

    def scan(self, threat: Threat) -> str:
        countermeasure = self.memory.match(threat.behavior)
        if countermeasure is None:
            return "UNKNOWN_THREAT"
        return countermeasure.name
