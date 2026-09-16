"""Protected immune memory: store the cure, not the specialist."""

from dataclasses import asdict
import json
from pathlib import Path

from .models import Countermeasure


class ImmuneMemory:
    """Small JSON-backed memory of validated countermeasures."""

    def __init__(self, path: str | Path = "memory/countermeasures.json") -> None:
        self.path = Path(path)
        self._entries: list[Countermeasure] = []

    def remember(self, countermeasure: Countermeasure) -> None:
        if countermeasure not in self._entries:
            self._entries.append(countermeasure)

    def match(self, behavior: set[str] | frozenset[str]) -> Countermeasure | None:
        """Return the most specific validated rule that matches this behavior.

        A broad rule must never win merely because it was stored earlier. More
        specific triggers take precedence, reducing accidental cross-family
        reuse as immune memory grows.
        """
        incoming = set(behavior)
        matches = [entry for entry in self._entries if entry.trigger.issubset(incoming)]
        if not matches:
            return None
        return max(matches, key=lambda entry: (len(entry.trigger), entry.name))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                **asdict(entry),
                "trigger": sorted(entry.trigger),
                "actions": list(entry.actions),
            }
            for entry in self._entries
        ]
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                raise ValueError("immune memory must be a list")

            entries: list[Countermeasure] = []
            for item in payload:
                if not isinstance(item, dict):
                    raise ValueError("invalid immune memory entry")
                trigger = item["trigger"]
                actions = item["actions"]
                if not isinstance(trigger, list) or not isinstance(actions, list):
                    raise ValueError("invalid immune memory fields")
                if not all(isinstance(value, str) for value in trigger + actions):
                    raise ValueError("immune memory fields must contain strings")
                entries.append(
                    Countermeasure(
                        name=str(item["name"]),
                        trigger=frozenset(trigger),
                        actions=tuple(actions),
                        rationale=str(item["rationale"]),
                    )
                )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            # Corrupted or manually altered memory must fail closed: do not
            # reuse an entry whose structure cannot be trusted.
            self._entries = []
            return

        self._entries = entries

    @property
    def entries(self) -> tuple[Countermeasure, ...]:
        return tuple(self._entries)
