"""Real host scanning lifecycle for BIOAEGIS."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .confidence import fuse
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
    confidence_level: str = "NONE"


class HostEngine:
    """Coordinates defensive actions while keeping investigation disposable."""

    def __init__(self, memory: ImmuneMemory | None = None, deep: bool = False) -> None:
        self.memory = memory or ImmuneMemory()
        self.memory.load()
        self.validator = Validator()
        self.scanner = HostScanner(deep=deep)
        self.quarantine = Quarantine()
        self.general = GeneralScanner(self.memory)

    def scan(
        self,
        target: str,
        quarantine: bool = False,
        automatic: bool = False,
    ) -> list[HostResult]:
        results: list[HostResult] = []
        for finding in self.scanner.scan(target):
            results.append(self._handle_finding(finding, quarantine, automatic))
        return results

    def _handle_finding(self, finding: HostFinding, quarantine: bool, automatic: bool) -> HostResult:
        confidence = fuse(finding.behaviors, external_hits=1 if finding.clamav else 0)
        threat = Threat(
            threat_id=finding.sha256,
            family="host-static-finding",
            behavior=finding.behaviors,
            resource=str(finding.path),
            variant="static",
        )

        candidate = self.memory.match(finding.behaviors)
        if candidate is None:
            specialist = HostSpecialist()
            report = specialist.investigate(finding)
            candidate = report.candidate
            result = self.validator.validate(threat, candidate)
            del specialist
        else:
            result = self.validator.validate(threat, candidate)

        if not result.accepted:
            return HostResult(
                finding, result, False, None,
                "Response rejected; no host action taken.", confidence.level,
            )

        if automatic and confidence.level != "HIGH":
            return HostResult(
                finding,
                result,
                False,
                None,
                f"Automatic protection held action at {confidence.level} confidence; review required.",
                confidence.level,
            )

        if not quarantine:
            return HostResult(
                finding,
                result,
                False,
                None,
                "Detection only; quarantine was not requested.",
                confidence.level,
            )

        try:
            record = self.quarantine.isolate(finding.path, finding.sha256)
        except (OSError, ValueError, shutil.Error) as exc:
            return HostResult(
                finding, result, False, None, f"Quarantine failed: {exc}", confidence.level
            )

        verified = (not finding.path.exists()) and Path(record.quarantine_path).is_file()
        if not verified:
            return HostResult(
                finding, result, False, record, "Quarantine verification failed.", confidence.level
            )

        if candidate is not None:
            self.memory.remember(candidate)
            self.memory.save()
            self.general = GeneralScanner(self.memory)

        return HostResult(
            finding,
            result,
            True,
            record,
            "Quarantined and verified; validated countermeasure remembered.",
            confidence.level,
        )
