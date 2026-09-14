"""Independent validation of specialist proposals."""

from .models import Countermeasure, Threat, ValidationResult

ALLOWED_ACTIONS = frozenset(
    {
        "SIMULATE_QUARANTINE_RESOURCE",
        "SIMULATE_REMOVE_PERSISTENCE",
        "SIMULATE_VERIFY_CLEAN_STATE",
    }
)


class Validator:
    """Checks a proposed response before it can enter immune memory."""

    def validate(self, threat: Threat, candidate: Countermeasure | None) -> ValidationResult:
        if candidate is None:
            return ValidationResult(False, {"candidate_exists": False}, "No countermeasure proposed.")

        checks = {
            "candidate_exists": True,
            "trigger_matches": candidate.trigger == threat.behavior,
            "actions_are_safe": set(candidate.actions).issubset(ALLOWED_ACTIONS),
            "has_recovery_check": "SIMULATE_VERIFY_CLEAN_STATE" in candidate.actions,
            "has_quarantine_step": "SIMULATE_QUARANTINE_RESOURCE" in candidate.actions,
        }
        accepted = all(checks.values())
        reason = "Countermeasure accepted." if accepted else "Countermeasure rejected by validator."
        return ValidationResult(accepted, checks, reason)
