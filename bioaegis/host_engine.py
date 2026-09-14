"""Real host scanning lifecycle for BIOAEGIS.

Flow: read-only scan -> known response or disposable specialist -> validator
-> optional reversible quarantine -> verification -> immune-memory update.
"""

from __future__ import annotations

from dataclasses import dataclass

from .general_scanner import GeneralScanner
from .host_scanner import HostFinding, HostScanner
from .host_specialist import HostSpecialist
from .memory import ImmuneMemory
from .models import Threat, ValidationResult
from .quarantine import Quarantine, QuarantineRecord
from .validator import Validator


@dataclass(frozen=True)
class HostResult:
    finding: HostFinding
    validation: ValidationResult | None
    quarantined: bool
    quarantine_record: QuarantineRecord | None
    message: str


class HostEngine:
    """Coordinates real defensive actions while keeping the specialist disposable."""

    def __init__(self, memory: ImmuneMemory | None = None) -> None:
        self.memory = memory or ImmuneMemory()
        self.memory.load()
        self.validator = Validator()
        self.scanner = HostScanner()
        self.specialist = HostSpecialist()
        self.quarantine = Quarantine()
        self.general = GeneralScanner(self.memory)

    def scan(self, target: str, quarantine: bool = False) -> list[HostResult]:
        results: list[HostResult] = []
        for finding in self.scanner.scan(target):
            result = self._handle_finding(finding, quarantine)
            results.append(result)
        return results

    def _handle_finding(self, finding: HostFinding, quarantine: bool) -> HostResult:
        threat = Threat(
            threat_id=finding.sha256,
            family="host-static-finding",
            behavior=finding.behaviors,
            resource=str(finding.path),
            variant="static",
        )

        known = self.general.scan(threat)
        candidate = self.memory.match(finding.behaviors) if known != "UNKNOWN_THREAT" else None

        if candidate is None:
            specialist = HostSpecialist()
            report = specialist.investigate(finding)
            candidate = report.candidate
            result = self.validator.validate(threat, candidate)
            del specialist
        else:
            result = self.validator.validate(threat, candidate)

        if not result.accepted:
            return HostResult(finding, result, False, None, "Response rejected; no host action taken.")

        if not quarantine:
            return HostResult(
                finding,
                result,
                False,
                None,
                "Detection only; use --quarantine to isolate the file.",
            )

        try:
            record = self.quarantine.isolate(finding.path, finding.sha256)
        except (OSError, ValueError, shutil.Error) as exc:
            return HostResult(finding, result, False, None, f"Quarantine failed: {exc}")

        verified = (not finding.path.exists()) and record.quarantine_path
        if not verified:
            return HostResult(finding, result, False, record, "Quarantine verification failed.")

        if candidate is not None:
            self.memory.remember(candidate)
            self.memory.save()
            self.general = GeneralScanner(self.memory)

        return HostResult(finding, result, True, record, "Quarantined and verified; countermeasure remembered.")
