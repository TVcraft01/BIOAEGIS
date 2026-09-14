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
        incoming = set(behavior)
        for entry in self._entries:
            if entry.trigger.issubset(incoming):
                return entry
        return None

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
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self._entries = [
            Countermeasure(
                name=item["name"],
                trigger=frozenset(item["trigger"]),
                actions=tuple(item["actions"]),
                rationale=item["rationale"],
            )
            for item in payload
        ]

    @property
    def entries(self) -> tuple[Countermeasure, ...]:
        return tuple(self._entries)
