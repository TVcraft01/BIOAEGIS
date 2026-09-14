from bioaegis.lifecycle import BioAegis
from bioaegis.models import Threat


def test_unknown_threat_is_learned_and_reused(tmp_path):
    memory_path = tmp_path / "countermeasures.json"
    from bioaegis.memory import ImmuneMemory

    memory = ImmuneMemory(memory_path)
    system = BioAegis(memory)
    threat = Threat(
        threat_id="fixture-001",
        family="simulated-trojan",
        behavior=frozenset({"persistence", "suspicious-write"}),
        resource="SIMULATED_RESOURCE",
        variant="A",
    )

    assert system.general.scan(threat) == "UNKNOWN_THREAT"
    result = system.handle(threat)
    assert result is not None
    assert result.accepted is True
    assert system.general.scan(threat) == "neutralize-simulated-trojan"

    # A variant with the same behavior can reuse the learned response.
    variant = Threat(
        threat_id="fixture-002",
        family="simulated-trojan",
        behavior=threat.behavior,
        resource="ANOTHER_SIMULATED_RESOURCE",
        variant="B",
    )
    assert system.general.scan(variant) == "neutralize-simulated-trojan"


def test_validator_rejects_unsafe_actions():
    from bioaegis.models import Countermeasure
    from bioaegis.validator import Validator

    threat = Threat("fixture", "family", frozenset({"x"}), "resource")
    unsafe = Countermeasure(
        "bad",
        threat.behavior,
        ("RUN_ARBITRARY_COMMAND",),
        "unsafe fixture",
    )
    result = Validator().validate(threat, unsafe)
    assert result.accepted is False
    assert result.checks["actions_are_safe"] is False
