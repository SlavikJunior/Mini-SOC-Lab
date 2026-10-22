"""Детекторы Windows Security / Sysmon событий (JSONL)."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from mini_soc_lab import mitre
from mini_soc_lab.models import Finding, any_of

LOLBIN_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("certutil.exe", "-urlcache", "T1105", "certutil used to download payload over HTTP(S)"),
    ("bitsadmin.exe", "/transfer", "T1105", "bitsadmin job used to download/upload files"),
    ("mshta.exe", "http", "T1218", "mshta executing remote script"),
    ("mshta.exe", ".hta", "T1218", "mshta executing local .hta script"),
    ("rundll32.exe", "javascript:", "T1218", "rundll32 executing javascript inline"),
    ("regsvr32.exe", "/i:http", "T1218", "regsvr32 with remote scriptlet (squiblydoo pattern)"),
    ("wbadmin.exe", "delete catalog", "T1485", "wbadmin deleting backup catalog (ransomware pattern)"),
    ("vssadmin.exe", "delete shadows", "T1490", "vssadmin deleting shadow copies (ransomware pattern)"),
)

SUSPICIOUS_PATH_PREFIXES = (
    "c:\\windows\\temp\\",
    "c:\\temp\\",
)

SUSPICIOUS_USER_DIRS = ("appdata\\roaming", "appdata\\local\\temp", "downloads", "public")

OFFICE_PARENTS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")


def _event_id(event: dict[str, Any]) -> str:
    return str(event.get("event_id"))


def detect_repeated_failed_logons(events: list[dict[str, Any]], threshold: int) -> list[Finding]:
    """Порог неудачных входов 4625 с одного IP (учебная эвристика brute force)."""
    failed = [e for e in events if _event_id(e) == "4625"]
    counts: Counter[str] = Counter(
        str(e["src_ip"]) for e in failed if e.get("src_ip") not in (None, "", "-")
    )
    findings: list[Finding] = []
    for ip, count in sorted(counts.items()):
        if count >= threshold:
            related = [e for e in failed if str(e.get("src_ip")) == ip]
            users = sorted({str(e.get("user")) for e in related})
            findings.append(Finding(
                source="windows",
                kind="repeated_failed_logons",
                severity="medium" if count < threshold * 2 else "high",
                evidence=f"Event ID 4625 (failed logon) repeated {count} times from one source IP",
                mitre=(mitre.ref("T1110.001"),),
                first_seen=min(str(e.get("timestamp", "")) for e in related),
                last_seen=max(str(e.get("timestamp", "")) for e in related),
                details={
                    "source_ip": ip,
                    "count": count,
                    "target_users": users,
                    "caveat": "Threshold is illustrative; confirm account, logon type and context.",
                },
            ))
    return findings


def detect_success_after_failures(events: list[dict[str, Any]], min_failures: int = 2) -> list[Finding]:
    """Успешный вход (4624) с того же IP, с которого были неудачные попытки."""
    failed = [e for e in events if _event_id(e) == "4625" and e.get("src_ip")]
    success = [e for e in events if _event_id(e) == "4624" and e.get("src_ip")]
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in failed:
        failures_by_ip[str(event["src_ip"])].append(event)
    findings: list[Finding] = []
    for ip, failed_events in failures_by_ip.items():
        if len(failed_events) < min_failures:
            continue
        for ok in success:
            if str(ok.get("src_ip")) != ip:
                continue
            findings.append(Finding(
                source="windows",
                kind="successful_logon_after_failures",
                severity="high",
                evidence=(
                    f"Successful logon (4624) from {ip} after {len(failed_events)} "
                    "failed attempts from the same IP"
                ),
                mitre=(mitre.ref("T1110.001"), mitre.ref("T1078")),
                first_seen=min(str(e.get("timestamp", "")) for e in failed_events),
                last_seen=str(ok.get("timestamp", "")),
                details={
                    "source_ip": ip,
                    "failed_count": len(failed_events),
                    "user": ok.get("user"),
                    "logon_type": ok.get("logon_type"),
                },
            ))
    return findings


def detect_powershell_encoded(events: list[dict[str, Any]]) -> list[Finding]:
    """PowerShell с EncodedCommand (учебный маркер Forgery-активности)."""
    findings: list[Finding] = []
    for event in events:
        if _event_id(event) not in {"1", "4688"}:
            continue
        blob = any_of(event, "image", "command_line")
        if "powershell.exe" in blob and (
            "-encodedcommand" in blob or re_enc_flag(blob)
        ):
            findings.append(Finding(
                source="windows",
                kind="powershell_encoded_command",
                severity="medium",
                evidence="PowerShell process command line contains EncodedCommand switch",
                mitre=(mitre.ref("T1059.001"), mitre.ref("T1027")),
                first_seen=str(event.get("timestamp", "")),
                details={
                    "host": event.get("host"),
                    "user": event.get("user"),
                    "image": event.get("image"),
                    "parent_image": event.get("parent_image"),
                    "command_line": event.get("command_line"),
                    "caveat": "Encoded commands can be legitimate; inspect parent and payload.",
                },
            ))
    return findings


def re_enc_flag(blob: str) -> bool:
    """Короткие формы -enc / -e с пробелом (проверка по границе слова)."""
    return any(
        f" {flag} " in f" {blob} " for flag in ("-enc", "-e")
    )


def detect_lolbins(events: list[dict[str, Any]]) -> list[Finding]:
    """LOLBin-активность по command_line (certutil, bitsadmin, mshta и т.д.)."""
    findings: list[Finding] = []
    for event in events:
        if _event_id(event) not in {"1", "4688"}:
            continue
        blob = any_of(event, "image", "command_line")
        for binary, arg, technique, evidence in LOLBIN_PATTERNS:
            if binary in blob and arg in blob:
                findings.append(Finding(
                    source="windows",
                    kind="lolbin_execution",
                    severity="high",
                    evidence=evidence,
                    mitre=(mitre.ref(technique),),
                    first_seen=str(event.get("timestamp", "")),
                    details={
                        "host": event.get("host"),
                        "user": event.get("user"),
                        "image": event.get("image"),
                        "command_line": event.get("command_line"),
                        "parent_image": event.get("parent_image"),
                    },
                ))
                break
    return findings


def detect_suspicious_path(events: list[dict[str, Any]]) -> list[Finding]:
    """Запуск исполняемого файла из временных/пользовательских каталогов."""
    findings: list[Finding] = []
    for event in events:
        if _event_id(event) not in {"1", "4688"}:
            continue
        image = str(event.get("image", "")).lower()
        if not image or image.startswith("c:\\windows\\") or image.startswith("\\device\\"):
            continue
        suspicious = image.startswith(SUSPICIOUS_PATH_PREFIXES[1:]) or (
            "\\users\\" in image and any(f"\\{d}" in image for d in SUSPICIOUS_USER_DIRS)
        )
        if not suspicious:
            continue
        findings.append(Finding(
            source="windows",
            kind="process_from_suspicious_path",
            severity="medium",
            evidence="Executable launched from user-writable temp/public directory",
            mitre=(mitre.ref("T1036"),),
            first_seen=str(event.get("timestamp", "")),
            details={
                "host": event.get("host"),
                "user": event.get("user"),
                "image": event.get("image"),
                "parent_image": event.get("parent_image"),
            },
        ))
    return findings


def detect_office_spawning_script(events: list[dict[str, Any]]) -> list[Finding]:
    """Дочерний интерпретатор (cmd/powershell/wscript) у офисного процесса."""
    findings: list[Finding] = []
    script_children = ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
    for event in events:
        if _event_id(event) not in {"1", "4688"}:
            continue
        parent = str(event.get("parent_image", "")).lower()
        child = str(event.get("image", "")).lower()
        if any(office in parent.split("\\")[-1] for office in OFFICE_PARENTS) and any(
            script in child.split("\\")[-1] for script in script_children
        ):
            findings.append(Finding(
                source="windows",
                kind="office_process_spawning_script",
                severity="high",
                evidence="Office application spawned a script interpreter (macro / dropper pattern)",
                mitre=(mitre.ref("T1204"), mitre.ref("T1059")),
                first_seen=str(event.get("timestamp", "")),
                details={
                    "host": event.get("host"),
                    "user": event.get("user"),
                    "image": event.get("image"),
                    "parent_image": event.get("parent_image"),
                    "command_line": event.get("command_line"),
                },
            ))
    return findings


def detect_suspicious_network(events: list[dict[str, Any]]) -> list[Finding]:
    """Sysmon Event ID 3: сетевое соединение с подозрительных процессов."""
    findings: list[Finding] = []
    for event in events:
        if _event_id(event) != "3":
            continue
        image = str(event.get("image", "")).lower()
        suspicious = (
            "powershell.exe" in image
            or "\\users\\" in image
            or "certutil" in image
            or "bitsadmin" in image
        )
        if not suspicious:
            continue
        findings.append(Finding(
            source="windows",
            kind="suspicious_network_connection",
            severity="medium",
            evidence="Network connection initiated by a script interpreter or user-writable binary",
            mitre=(mitre.ref("T1071"),),
            first_seen=str(event.get("timestamp", "")),
            details={
                "host": event.get("host"),
                "process": event.get("image"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get("destination_port"),
                "protocol": event.get("protocol"),
            },
        ))
    return findings


def detect_findings(events: list[dict[str, Any]], threshold: int = 3) -> list[Finding]:
    """Все Windows-детекции для набора событий."""
    findings: list[Finding] = []
    findings.extend(detect_repeated_failed_logons(events, threshold))
    findings.extend(detect_success_after_failures(events))
    findings.extend(detect_powershell_encoded(events))
    findings.extend(detect_lolbins(events))
    findings.extend(detect_suspicious_path(events))
    findings.extend(detect_office_spawning_script(events))
    findings.extend(detect_suspicious_network(events))
    return findings
