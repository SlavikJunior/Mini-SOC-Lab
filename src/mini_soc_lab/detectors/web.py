"""Детекторы web (nginx access log) — OWASP-классифицируемые атаки."""
from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import unquote

from mini_soc_lab import mitre
from mini_soc_lab.models import Finding

# Marкеризованные паттерны SQL-инъекций в URL/строке запроса (учебный набор)
SQLI_PATTERNS = (
    "' or '1", "' or 1=1", "1=1--", "union select", "union all select",
    "sleep(", "benchmark(", "or 1='1", "; drop table", "'--", "admin'--",
)

TRAVERSAL_MARKERS = ("../", "%2e%2e", "..\\")

SCANNER_AGENTS = ("sqlmap", "nikto", "nmap scripting engine", "masscan", "dirbuster", "gobuster")


def _decode(path: str) -> str:
    return unquote(path).lower()


def detect_sqli(events: list[dict[str, Any]]) -> list[Finding]:
    """Признаки SQL-инъекции в URL (T1190)."""
    findings: list[Finding] = []
    for event in events:
        url = _decode(str(event.get("path", "")))
        hit = next((p for p in SQLI_PATTERNS if p in url), None)
        if hit:
            findings.append(Finding(
                source="web",
                kind="web_sqli_attempt",
                severity="high",
                evidence=f"SQL injection pattern in URL: {hit!r}",
                mitre=(mitre.ref("T1190"),),
                first_seen=str(event.get("timestamp", "")),
                details={
                    "src_ip": event.get("src_ip"),
                    "method": event.get("method"),
                    "path": event.get("path"),
                    "status": event.get("status"),
                    "user_agent": event.get("user_agent"),
                    "caveat": "Confirm against application behavior; check whether response leaked data.",
                },
            ))
    return findings


def detect_traversal(events: list[dict[str, Any]]) -> list[Finding]:
    """Path traversal / LFI попытки в URL (T1190)."""
    findings: list[Finding] = []
    for event in events:
        raw = str(event.get("path", ""))
        url = _decode(raw)
        if any(marker in url for marker in TRAVERSAL_MARKERS) or "/etc/passwd" in url:
            findings.append(Finding(
                source="web",
                kind="web_path_traversal",
                severity="high",
                evidence="Directory traversal pattern attempting to escape web root",
                mitre=(mitre.ref("T1190"),),
                first_seen=str(event.get("timestamp", "")),
                details={
                    "src_ip": event.get("src_ip"),
                    "path": raw,
                    "status": event.get("status"),
                },
            ))
    return findings


def detect_scanning(events: list[dict[str, Any]], min_404: int = 20) -> list[Finding]:
    """Сканирование приложения: массовые 404 или известный сканер в user_agent."""
    by_ip_404: dict[str, set[str]] = defaultdict(set)
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}
    scanner_ips: dict[str, dict[str, Any]] = {}
    for event in events:
        ip = str(event.get("src_ip"))
        status = int(event.get("status", 0) or 0)
        ts = str(event.get("timestamp", ""))
        if status in (404, 400, 403):
            by_ip_404[ip].add(str(event.get("path")))
            first_seen.setdefault(ip, ts)
            last_seen[ip] = ts
        agent = str(event.get("user_agent", "")).lower()
        if any(name in agent for name in SCANNER_AGENTS):
            entry = scanner_ips.setdefault(ip, {
                "agent": event.get("user_agent"), "count": 0, "first": ts, "last": ts})
            entry["count"] += 1
            entry["last"] = ts
    findings = [
        Finding(
            source="web",
            kind="web_scanner_user_agent",
            severity="medium",
            evidence=f"Known security scanner user agent: {entry['agent']}",
            mitre=(mitre.ref("T1595.002"),),
            first_seen=entry["first"],
            last_seen=entry["last"],
            details={"src_ip": ip, "requests": entry["count"]},
        )
        for ip, entry in scanner_ips.items()
    ]
    for ip, paths in by_ip_404.items():
        if len(paths) >= min_404:
            findings.append(Finding(
                source="web",
                kind="web_mass_404_scanning",
                severity="medium",
                evidence=f"{len(paths)} distinct failed paths requested from one IP (directory brute-forcing)",
                mitre=(mitre.ref("T1595.002"),),
                first_seen=first_seen.get(ip),
                last_seen=last_seen.get(ip),
                details={"src_ip": ip, "distinct_paths": len(paths)},
            ))
    return findings


def detect_auth_bruteforce(events: list[dict[str, Any]], min_failures: int = 10) -> list[Finding]:
    """Brute force авторизации: много неуспешных POST на auth-эндпоинты."""
    login_paths = ("/login", "/signin", "/auth", "/wp-login.php", "/api/login")
    failures: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        path = _decode(str(event.get("path", ""))).split("?")[0]
        status = int(event.get("status", 0) or 0)
        if event.get("method") == "POST" and status in (401, 403, 422, 500) and any(
            p in path for p in login_paths
        ):
            failures[str(event.get("src_ip"))].append(event)
    findings: list[Finding] = []
    for ip, failed_events in failures.items():
        if len(failed_events) >= min_failures:
            findings.append(Finding(
                source="web",
                kind="web_auth_bruteforce",
                severity="high",
                evidence=f"{len(failed_events)} failed POST attempts at auth endpoint from one IP",
                mitre=(mitre.ref("T1110.001"),),
                first_seen=min(str(e.get("timestamp", "")) for e in failed_events),
                last_seen=max(str(e.get("timestamp", "")) for e in failed_events),
                details={"src_ip": ip, "count": len(failed_events)},
            ))
    return findings


def detect_findings(events: list[dict[str, Any]], threshold: int = 10) -> list[Finding]:
    """Все web-детекции для набора событий."""
    findings: list[Finding] = []
    findings.extend(detect_sqli(events))
    findings.extend(detect_traversal(events))
    findings.extend(detect_scanning(events, min_404=threshold))
    findings.extend(detect_auth_bruteforce(events, min_failures=threshold))
    return findings
