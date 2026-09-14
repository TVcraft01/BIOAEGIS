"""Disposable specialist for static host findings.

This is deliberately deterministic. It is the safe specialist baseline that
can later be replaced by an isolated ML/model-backed specialist without
changing the validator or quarantine contract.
"""

from .host_scanner import HostFinding
from .models import Countermeasure, SpecialistReport


class HostSpecialist:
    """Analyze one finding and propose only the safe quarantine response."""

    def investigate(self, finding: HostFinding) -> SpecialistReport:
        if finding.clamav:
            rationale = "Independent signature evidence supports isolating the file."
        else:
            rationale = "Multiple static suspicious behaviors support isolating the file for review."

        candidate = Countermeasure(
            name="quarantine-suspicious-file",
            trigger=finding.behaviors,
            actions=("QUARANTINE_FILE", "VERIFY_QUARANTINE"),
            rationale=rationale,
        )
        return SpecialistReport(
            threat_id=finding.sha256,
            candidate=candidate,
            observations=list(finding.evidence),
            metadata={
                "path": str(finding.path),
                "sha256": finding.sha256,
                "score": finding.score,
                "clamav": finding.clamav,
            },
        )
