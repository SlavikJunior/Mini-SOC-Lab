"""Тесты web-детекторов (nginx access log): детекция + false positive корпус."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

pkg = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(pkg))

from mini_soc_lab.detectors import web  # noqa: E402
from mini_soc_lab.loaders import load_nginx_access  # noqa: E402

LOGS = Path(__file__).resolve().parents[1] / "logs"


def web_events() -> list[dict[str, Any]]:
    return load_nginx_access(LOGS / "web_access.log")


def kinds(findings: list[Any]) -> set[str]:
    return {f.kind for f in findings}


def test_web_dataset_covers_all_finding_types() -> None:
    findings = web.detect_findings(web_events(), threshold=10)
    expected = {"web_sqli_attempt", "web_path_traversal", "web_mass_404_scanning",
                "web_auth_bruteforce", "web_scanner_user_agent"}
    assert expected <= kinds(findings)


def test_sqli_hits_url_and_details() -> None:
    events = web_events()
    findings = web.detect_sqli(events)
    assert findings, "SQLi attempts in sample log should be detected"
    sample = findings[0].details
    assert "src_ip" in sample and "path" in sample


def test_scanner_aggregated_per_ip() -> None:
    events = web_events()
    scanner = [f for f in web.detect_scanning(events) if f.kind == "web_scanner_user_agent"]
    ips = [f.details["src_ip"] for f in scanner]
    assert len(ips) == len(set(ips)), "scanner findings must be aggregated per IP"


# --- Ложные срабатывания -----------------------------------------------------

def test_normal_traffic_is_clean() -> None:
    clean: list[dict[str, Any]] = []
    for idx in range(30):
        clean.append({
            "timestamp": f"2026-10-22T0{idx % 10}:1{idx % 9}:00Z",
            "src_ip": "198.51.100.3", "method": "GET",
            "path": ["/", "/shop", "/shop/checkout", "/assets/style.css", "/healthz"][idx % 5],
            "status": 200, "bytes": 1024, "user_agent": "Mozilla/5.0 Chrome/120.0"})
    assert web.detect_findings(clean, threshold=10) == []


def test_few_404_from_one_ip_is_clean() -> None:
    events = [{"timestamp": "2026-10-22T10:00:00Z", "src_ip": "192.0.2.6", "method": "GET",
               "path": f"/page/{i}", "status": 404, "bytes": 153, "user_agent": "Mozilla/5.0"}
              for i in range(5)]
    assert not web.detect_scanning(events, min_404=20)


def test_successful_logins_are_not_bruteforce() -> None:
    events = [{"timestamp": f"2026-10-22T{i // 10}:{i % 60}:00Z", "src_ip": "192.0.2.7",
               "method": "POST", "path": "/login", "status": 200, "bytes": 640,
               "user_agent": "Mozilla/5.0"} for i in range(15)]
    assert not web.detect_auth_bruteforce(events)


def test_url_encoded_traversal_is_decoded() -> None:
    events = [{"timestamp": "2026-10-22T10:00:00Z", "src_ip": "203.0.113.1", "method": "GET",
               "path": "/file?name=..%2F..%2Fetc%2Fpasswd", "status": 200, "bytes": 10,
               "user_agent": "curl/8.0"}]
    assert len(web.detect_traversal(events)) == 1
