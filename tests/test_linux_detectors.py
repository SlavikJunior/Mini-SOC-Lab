"""Тесты linux-детекторов (auth.log) + парсеров загрузчиков."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

pkg = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(pkg))

from mini_soc_lab.detectors import linux as det_linux  # noqa: E402
from mini_soc_lab.loaders import load_syslog_auth  # noqa: E402

LOGS = Path(__file__).resolve().parents[1] / "logs"


def auth_events() -> list[dict[str, Any]]:
    return load_syslog_auth(LOGS / "auth.log")


def test_auth_parser_extracts_sshd_and_sudo() -> None:
    events = auth_events()
    kinds = {e["event_id"] for e in events}
    assert {"sshd_auth_failed", "sshd_auth_success", "sudo_failure", "other"} <= kinds
    failed = [e for e in events if e["event_id"] == "sshd_auth_failed"]
    assert all(e["src_ip"].startswith("203.0.113.") for e in failed)


def test_linux_dataset_detects_bruteforce_and_success() -> None:
    kinds = {f.kind for f in det_linux.detect_findings(auth_events())}
    assert "linux_ssh_bruteforce" in kinds
    assert "linux_ssh_success_after_failures" in kinds


def test_malformed_syslog_line_raises_with_position() -> None:
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
        handle.write("Oct 23 11:12:34 LAB-UBU01 Broken line without process\n")
        path = Path(handle.name)
    try:
        with pytest.raises(ValueError, match="unexpected syslog line"):
            load_syslog_auth(path)
    finally:
        path.unlink(missing_ok=True)


# --- Ложные срабатывания -----------------------------------------------------

def test_single_failed_password_is_clean() -> None:
    events = [{"event_id": "sshd_auth_failed", "src_ip": "192.0.2.4", "user": "dev",
               "timestamp": "2026-10-23T09:00:00Z"}]
    assert det_linux.detect_ssh_bruteforce(events, threshold=5) == []


def test_success_from_other_ip_is_clean() -> None:
    events = [
        {"event_id": "sshd_auth_failed", "src_ip": "203.0.113.5", "user": "root",
         "timestamp": "2026-10-23T09:00:00Z"} for _ in range(4)
    ] + [{"event_id": "sshd_auth_success", "src_ip": "192.0.2.4", "user": "root",
          "timestamp": "2026-10-23T09:05:00Z"}]
    assert det_linux.detect_ssh_success_after_failures(events) == []


def test_two_sudo_failures_are_clean() -> None:
    events = [{"event_id": "sudo_failure", "host": "HOST", "user": "deploy",
               "timestamp": f"2026-10-23T09:0{i}:00Z"} for i in range(2)]
    assert det_linux.detect_sudo_abuse(events, threshold=3) == []
