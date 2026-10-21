import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "analyze_events.py"
spec = importlib.util.spec_from_file_location("analyze_events", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_sample_dataset_detects_repeated_failed_logons_and_encoded_powershell():
    events = module.load_events(Path(__file__).resolve().parents[1] / "logs" / "sample_events.jsonl")
    report = module.analyze(events)
    kinds = {finding["type"] for finding in report["findings"]}
    assert report["event_count"] == 10
    assert report["failed_logon_count"] == 3
    assert "repeated_failed_logons" in kinds
    assert "powershell_encoded_command" in kinds


def test_threshold_can_be_adjusted():
    events = [
        {"event_id": 4625, "src_ip": "198.51.100.10", "timestamp": "2026-10-01T00:00:00Z"},
        {"event_id": 4625, "src_ip": "198.51.100.10", "timestamp": "2026-10-01T00:00:01Z"},
    ]
    assert module.analyze(events, brute_force_threshold=3)["findings_count"] == 0
    assert module.analyze(events, brute_force_threshold=2)["findings_count"] == 1


def test_empty_events():
    report = module.analyze([])
    assert report["event_count"] == 0
    assert report["findings"] == []
