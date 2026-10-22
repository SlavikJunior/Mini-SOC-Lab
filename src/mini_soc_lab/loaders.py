"""Загрузчики событий: JSONL, nginx access log, syslog auth.log.

Все парсеры устойчивы к битым строкам: повреждённая строка вызывает
ValueError с указанием номера строки, а не "тихий" пропуск.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

NGINX_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)'
    r' (?P<proto>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Загрузить JSONL: одна строка — один JSON-объект."""
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"{path.name}:{line_number}: must contain a JSON object")
            events.append(event)
    return events


def _parse_nginx_time(raw: str) -> str:
    """nginx: 22/Oct/2026:03:14:15 +0000 -> ISO 8601."""
    months = {m: i for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
    match = re.match(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})", raw)
    if match is None:
        raise ValueError(f"unparseable nginx time: {raw!r}")
    day, mon, year, hh, mm, ss, tz = match.groups()
    month = months.get(mon, 1)
    tzn = tz[:3] + ":" + tz[3:]
    return f"{year}-{month:02d}-{int(day):02d}T{hh}:{mm}:{ss}{tzn}"


def _parse_syslog_time(month: str, day: str, clock: str) -> str:
    """syslog без года — использовать текущий год (учебный формат)."""
    months = {m: i for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
    month_num = months.get(month, 1)
    return f"2026-{month_num:02d}-{int(day):02d}T{clock}Z"


def load_nginx_access(path: Path) -> list[dict[str, Any]]:
    """Разобрать access.log в combined-формате."""
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            match = NGINX_COMBINED.match(line)
            if match is None:
                raise ValueError(f"{path.name}:{line_number}: unexpected access.log line")
            data = match.groupdict()
            events.append({
                "timestamp": _parse_nginx_time(data["time"]),
                "src_ip": data["ip"],
                "method": data["method"],
                "path": data["path"],
                "status": int(data["status"]),
                "bytes": int(data["bytes"]),
                "user_agent": data.get("agent") or "",
                "message": "HTTP request",
            })
    return events


def load_syslog_auth(path: Path) -> list[dict[str, Any]]:
    """Разобрать auth.log (syslog: sshd, sudo, su)."""
    events: list[dict[str, Any]] = []
    auth_failed = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )
    auth_success = re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )
    sudo_failed = re.compile(r"(?:incorrect password attempts|NOT in sudoers|command not allowed)")
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            match = SYSLOG.match(line)
            if match is None:
                raise ValueError(f"{path.name}:{line_number}: unexpected syslog line")
            data = match.groupdict()
            message = data["message"]
            event: dict[str, Any] = {
                "timestamp": _parse_syslog_time(data["month"], data["day"], data["time"]),
                "host": data["host"],
                "source": data["process"],
                "message": message,
            }
            failed = auth_failed.match(message)
            success = auth_success.match(message)
            if data["process"] == "sshd" and failed:
                event.update({"event_id": "sshd_auth_failed", "user": failed.group("user"),
                              "src_ip": failed.group("ip")})
            elif data["process"] == "sshd" and success:
                event.update({"event_id": "sshd_auth_success", "user": success.group("user"),
                              "src_ip": success.group("ip")})
            elif data["process"] == "sudo" and sudo_failed.search(message):
                event["event_id"] = "sudo_failure"
            elif data["process"] == "sshd":
                event["event_id"] = "sshd_other"
            else:
                event["event_id"] = "other"
            events.append(event)
    return events


LOADERS: dict[str, Callable[[Path], list[dict[str, Any]]]] = {
    "windows": load_jsonl,
    "web": load_nginx_access,
    "linux": load_syslog_auth,
}


def load_source(source: str, path: Path) -> list[dict[str, Any]]:
    """Загрузить логи нужного источника выбранным парсером."""
    try:
        loader = LOADERS[source]
    except KeyError as exc:
        raise ValueError(f"unknown source: {source}") from exc
    return loader(path)
