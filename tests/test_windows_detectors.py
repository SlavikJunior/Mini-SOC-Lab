"""Тесты детекторов Windows: детекция + отсутствие ложных срабатываний."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

pkg = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(pkg))

from mini_soc_lab.detectors import windows  # noqa: E402
from mini_soc_lab.loaders import load_jsonl  # noqa: E402
from mini_soc_lab.models import Finding  # noqa: E402

LOGS = Path(__file__).resolve().parents[1] / "logs"


def expanded_events() -> list[dict[str, Any]]:
    return load_jsonl(LOGS / "windows_events.jsonl")


def kinds(findings: list[Finding]) -> set[str]:
    return {f.kind for f in findings}


# --- Основные детекции --------------------------------------------------------

def test_windows_dataset_covers_all_finding_types() -> None:
    findings = windows.detect_findings(expanded_events())
    expected = {
        "repeated_failed_logons",
        "successful_logon_after_failures",
        "powershell_encoded_command",
        "lolbin_execution",
        "process_from_suspicious_path",
        "office_process_spawning_script",
        "suspicious_network_connection",
    }
    assert expected <= kinds(findings)


def test_mitre_refs_are_populated() -> None:
    for finding in windows.detect_findings(expanded_events()):
        assert finding.mitre, f"finding {finding.kind} has no MITRE technique"


def test_threshold_can_be_adjusted() -> None:
    events = [
        {"event_id": 4625, "src_ip": "198.51.100.10", "timestamp": "2026-10-01T00:00:00Z"},
        {"event_id": 4625, "src_ip": "198.51.100.10", "timestamp": "2026-10-01T00:00:01Z"},
    ]
    assert not windows.detect_repeated_failed_logons(events, threshold=3)
    assert len(windows.detect_repeated_failed_logons(events, threshold=2)) == 1


def test_empty_events_produce_no_findings() -> None:
    assert windows.detect_findings([]) == []


# --- Ложные срабатывания (false positive corpus) ------------------------------

def test_legitimate_admin_activity_is_clean() -> None:
    """Легитимные админ-действия не должны давать находок."""
    clean_events: list[dict[str, Any]] = [
        {"event_id": 4624, "user": "svc_deploy", "src_ip": "192.0.2.10", "logon_type": 10,
         "timestamp": "2026-10-20T08:00:00Z", "message": "RDP logon from jump host"},
        {"event_id": 4688, "user": "svc_deploy", "image": "C:\\Windows\\System32\\cmd.exe",
         "parent_image": "C:\\Windows\\System32\\taskhostw.exe",
         "command_line": "cmd.exe /c ipconfig /all",
         "timestamp": "2026-10-20T08:05:00Z", "message": "Network diagnostics"},
        {"event_id": 4625, "user": "svc_batch", "src_ip": "192.0.2.11",
         "timestamp": "2026-10-20T08:12:00Z",
         "message": "Expired service password before rotation ticket"},
        {"event_id": 3, "image": "C:\\Windows\\System32\\svchost.exe",
         "destination_ip": "192.0.2.55", "destination_port": 443,
         "timestamp": "2026-10-20T08:20:00Z", "message": "Windows Update"},
        {"event_id": 1, "user": "svc_deploy", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "parent_image": "C:\\Windows\\explorer.exe",
         "command_line": "powershell.exe -NoProfile -Command Get-Service wuauserv",
         "timestamp": "2026-10-20T08:31:00Z", "message": "Service check"},
    ]
    assert windows.detect_findings(clean_events) == []


def test_failures_below_threshold_are_clean() -> None:
    events = [{"event_id": 4625, "src_ip": "192.0.2.20", "timestamp": "2026-10-20T09:00:00Z"}]
    assert not windows.detect_repeated_failed_logons(events, threshold=3)


def test_success_from_different_ip_is_not_flagged() -> None:
    events = [
        {"event_id": 4625, "src_ip": "203.0.113.9", "timestamp": "2026-10-20T09:00:00Z"},
        {"event_id": 4625, "src_ip": "203.0.113.9", "timestamp": "2026-10-20T09:00:05Z"},
        {"event_id": 4624, "src_ip": "198.51.100.2", "timestamp": "2026-10-20T09:01:00Z"},
    ]
    assert not windows.detect_success_after_failures(events, min_failures=2)


def test_plain_windows_binary_in_system_path_is_clean() -> None:
    events = [{"event_id": 1, "image": "C:\\Windows\\System32\\notepad.exe",
               "parent_image": "C:\\Windows\\explorer.exe", "command_line": "notepad.exe",
               "timestamp": "2026-10-20T09:00:00Z"}]
    assert windows.detect_suspicious_path(events) == []
    assert windows.detect_lolbins(events) == []


@pytest.mark.parametrize("command_line", [
    "powershell.exe -NoProfile -Command Get-EventLog System -Newest 5",
    "powershell.exe -Command \"Get-ChildItem | Select Name\"",
])
def test_plain_powershell_without_encoding_is_clean(command_line: str) -> None:
    events = [{"event_id": 1, "image": "C:\\...\\powershell.exe", "command_line": command_line,
               "timestamp": "2026-10-20T09:00:00Z"}]
    assert windows.detect_powershell_encoded(events) == []
