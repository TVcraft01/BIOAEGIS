"""Disposable specialist: investigate a threat and propose a cure."""

from .models import Countermeasure, SpecialistReport, Threat


class Specialist:
    """A short-lived researcher with no authority to execute system actions."""

    def investigate(self, threat: Threat) -> SpecialistReport:
        # The prototype only emits declarative, simulated actions.
        actions = (
            "SIMULATE_QUARANTINE_RESOURCE",
            "SIMULATE_REMOVE_PERSISTENCE",
            "SIMULATE_VERIFY_CLEAN_STATE",
        )
        candidate = Countermeasure(
            name=f"neutralize-{threat.family}",
            trigger=threat.behavior,
            actions=actions,
            rationale="Contain the simulated threat, remove its simulated persistence, then verify recovery.",
        )
        return SpecialistReport(
            threat_id=threat.threat_id,
            candidate=candidate,
            observations=[
                f"Observed behavior: {', '.join(sorted(threat.behavior))}",
                "No host commands were generated or executed.",
            ],
        )
