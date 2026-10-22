"""Детекторы Linux auth.log (sshd / sudo)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from mini_soc_lab import mitre
from mini_soc_lab.models import Finding


def _kind(event: dict[str, Any]) -> str:
    return str(event.get("event_id", ""))


def detect_ssh_bruteforce(events: list[dict[str, Any]], threshold: int = 5) -> list[Finding]:
    """Много неудачных паролей sshd с одного IP."""
    failed = [e for e in events if _kind(e) == "sshd_auth_failed"]
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in failed:
        by_ip[str(event.get("src_ip"))].append(event)
    findings: list[Finding] = []
    for ip, failed_events in sorted(by_ip.items()):
        if len(failed_events) >= threshold:
            users = sorted({str(e.get("user")) for e in failed_events})
            findings.append(Finding(
                source="linux",
                kind="linux_ssh_bruteforce",
                severity="medium" if len(failed_events) < threshold * 2 else "high",
                evidence=(
                    f"sshd: {len(failed_events)} failed password attempts from one source IP"
                ),
                mitre=(mitre.ref("T1110"),),
                first_seen=min(str(e.get("timestamp", "")) for e in failed_events),
                last_seen=max(str(e.get("timestamp", "")) for e in failed_events),
                details={
                    "source_ip": ip,
                    "count": len(failed_events),
                    "target_users": users,
                },
            ))
    return findings


def detect_ssh_success_after_failures(events: list[dict[str, Any]], min_failures: int = 3) -> list[Finding]:
    """Accepted password/publickey с IP после серии неудач — потенциальный компрометированный вход."""
    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    successes: list[dict[str, Any]] = []
    for event in events:
        if _kind(event) == "sshd_auth_failed":
            failed_by_ip[str(event.get("src_ip"))].append(event)
        elif _kind(event) == "sshd_auth_success":
            successes.append(event)
    findings: list[Finding] = []
    for ip, failed_events in failed_by_ip.items():
        if len(failed_events) < min_failures:
            continue
        for ok in successes:
            if str(ok.get("src_ip")) != ip:
                continue
            findings.append(Finding(
                source="linux",
                kind="linux_ssh_success_after_failures",
                severity="high",
                evidence=(
                    f"sshd: successful authentication from {ip} after "
                    f"{len(failed_events)} failed attempts from the same IP"
                ),
                mitre=(mitre.ref("T1110"), mitre.ref("T1078.003")),
                first_seen=min(str(e.get("timestamp", "")) for e in failed_events),
                last_seen=str(ok.get("timestamp", "")),
                details={"source_ip": ip, "user": ok.get("user"), "failed_count": len(failed_events)},
            ))
    return findings


def detect_sudo_abuse(events: list[dict[str, Any]], threshold: int = 3) -> list[Finding]:
    """Неудачные попытки sudo: перебор пароля или запрещённых команд."""
    sudo_failures = [e for e in events if _kind(e) == "sudo_failure"]
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in sudo_failures:
        by_user[str(event.get("host")) + ":" + str(event.get("user", "-"))].append(event)
    findings: list[Finding] = []
    for key, group in sorted(by_user.items()):
        if len(group) >= threshold:
            host, user = key.split(":", 1)
            findings.append(Finding(
                source="linux",
                kind="linux_sudo_failures",
                severity="medium",
                evidence=f"sudo: {len(group)} failed attempts (wrong password or disallowed command)",
                mitre=(mitre.ref("T1548"),),
                first_seen=min(str(e.get("timestamp", "")) for e in group),
                last_seen=max(str(e.get("timestamp", "")) for e in group),
                details={"host": host, "count": len(group)},
            ))
    return findings


def detect_findings(events: list[dict[str, Any]], threshold: int = 5) -> list[Finding]:
    """Все Linux-детекции для набора событий."""
    findings: list[Finding] = []
    findings.extend(detect_ssh_bruteforce(events, threshold))
    findings.extend(detect_ssh_success_after_failures(events))
    findings.extend(detect_sudo_abuse(events))
    return findings
