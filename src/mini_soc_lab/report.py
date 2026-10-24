"""Сборка отчёта из находок разных источников и рендеры JSON/HTML."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mini_soc_lab import mitre
from mini_soc_lab.models import SEVERITY_ORDER, Finding

LIMITATIONS = [
    "Educational heuristics on synthetic data; not a SIEM and not a Sigma engine.",
    "Thresholds are illustrative and tuned for the sample datasets.",
    "Every finding requires analyst validation in context.",
]

SAMPLE_NOTE = (
    "All events are synthetic (documentation-reserved IPs, .test domains, "
    "REDACTED_DEMO markers). Not real organizational logs."
)


def build_report(
    findings: list[Finding],
    stats: dict[str, dict[str, int]],
    threshold: int,
) -> dict[str, Any]:
    """Собрать единый отчёт: находки, статистика, MITRE coverage."""
    dicts = [f.to_dict() for f in findings]
    dicts.sort(
        key=lambda d: (
            -SEVERITY_ORDER.get(str(d.get("severity")), 0),
            str(d.get("first_seen") or d.get("timestamp") or ""),
        )
    )
    counts: dict[str, int] = {}
    for severity in SEVERITY_ORDER:
        counts[severity] = sum(1 for d in dicts if d.get("severity") == severity)
    return {
        "report": "mini-soc-lab",
        "threshold": threshold,
        "sources": stats,
        "event_count": sum(s.get("events", 0) for s in stats.values()),
        "findings_count": len(dicts),
        "severity_counts": counts,
        "findings": dicts,
        "mitre_coverage": mitre.coverage_table(dicts),
        "note": SAMPLE_NOTE,
        "limitations": LIMITATIONS,
    }


def write_json(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


HTML_TEMPLATE_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Mini SOC Lab — Analysis Report</title>
<style>
  :root {{ --bg:#0e1520; --panel:#16202e; --ink:#dbe4f0; --muted:#8b9bab;
          --accent:#3ecfb2; --high:#ff5d5d; --med:#ffb454; --low:#6db3f2; --info:#9aa7b6; }}
  body {{ background:var(--bg); color:var(--ink); font-family:-apple-system,'Segoe UI',Roboto,sans-serif;
         margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:16px; color:var(--accent); margin:28px 0 10px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:24px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }}
  .card {{ background:var(--panel); border-radius:10px; padding:14px 20px; min-width:120px; }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border-radius:10px;
          overflow:hidden; font-size:13px; }}
  th {{ text-align:left; color:var(--muted); font-weight:600; padding:10px 14px;
       border-bottom:1px solid #243044; }}
  td {{ padding:10px 14px; border-bottom:1px solid #1d2838; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .sev {{ display:inline-block; padding:2px 10px; border-radius:12px; font-weight:700;
         font-size:11px; text-transform:uppercase; }}
  .sev.high {{ background:var(--high); color:#1c0d0d; }}
  .sev.medium {{ background:var(--med); color:#221a06; }}
  .sev.low {{ background:var(--low); color:#0b1c2e; }}
  .sev.info {{ background:var(--info); color:#101820; }}
  code {{ color:var(--accent); font-size:12px; }}
  .foot {{ color:var(--muted); font-size:12px; margin-top:28px; line-height:1.6; }}
</style>
</head>
<body>
<h1>Mini SOC Lab — Analysis Report</h1>
<div class="sub">Synthetic educational data · thresholds are illustrative · every finding needs analyst validation</div>
"""


def _finding_row(dct: dict[str, Any]) -> str:
    severity = str(dct.get("severity", "info"))
    mitre_html = "<br>".join(
        f"<a style='color:var(--low)' href='https://attack.mitre.org/techniques/"
        f"{str(m['technique_id']).replace('.', '/')}/'>{m['technique_id']} {m['name']}</a>"
        + f" <span class='sub'>({m['tactic']})</span>"
        for m in dct.get("mitre", [])
    ) or "—"
    keep = ("source_ip", "src_ip", "count", "user", "image", "command_line", "path",
            "destination_ip", "target_users")
    extra = "<br>".join(
        f"<code>{k}: {dct[k]}</code>" for k in keep if k in dct and dct[k] not in (None, "")
    )
    return (
        "<tr>"
        f"<td><span class='sev {severity}'>{severity}</span></td>"
        f"<td>{dct.get('first_seen') or ''}</td>"
        f"<td><b>{dct.get('source')}</b><br><code>{dct.get('type')}</code></td>"
        f"<td>{dct.get('evidence', '')}{extra}</td>"
        f"<td>{mitre_html}</td>"
        "</tr>"
    )


def _mitre_table(rows: list[dict[str, str]]) -> str:
    body = "".join(
        f"<tr><td><code>{r['technique_id']}</code></td><td>{r['name']}</td>"
        f"<td>{r['tactic']}</td><td>{r['findings']}</td></tr>"
        for r in rows
    )
    return (
        "<table><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Findings</th></tr>"
        + (body or "<tr><td colspan=4>No coverage yet</td></tr>") + "</table>"
    )


def render_html(report: dict[str, Any]) -> str:
    """Собрать самодостаточный HTML-отчёт (встроенный CSS, без внешних зависимостей)."""
    parts = [HTML_TEMPLATE_HEAD]
    counts = report.get("severity_counts", {})
    parts.append("<div class='cards'>")
    parts.append(
        f"<div class='card'><div class='num'>{report.get('event_count', 0)}</div>"
        "<div class='lbl'>Events</div></div>"
        f"<div class='card'><div class='num'>{report.get('findings_count', 0)}</div>"
        "<div class='lbl'>Findings</div></div>"
    )
    for severity in ("critical", "high", "medium", "low"):
        parts.append(
            f"<div class='card'><div class='num'>{counts.get(severity, 0)}</div>"
            f"<div class='lbl sev {severity}'>{severity}</div></div>"
        )
    parts.append("</div>")

    parts.append("<h2>Findings (sorted by severity)</h2>")
    parts.append(
        "<table><tr><th>Severity</th><th>Time</th><th>Source / Type</th>"
        "<th>Evidence</th><th>MITRE ATT&amp;CK</th></tr>"
    )
    for dct in report.get("findings", []):
        parts.append(_finding_row(dct))
    parts.append("</table>")

    parts.append("<h2>MITRE ATT&amp;CK Coverage</h2>")
    parts.append(_mitre_table(list(report.get("mitre_coverage", []))))

    src = report.get("sources", {})
    src_rows = "".join(
        f"<tr><td>{name}</td><td>{s.get('events', 0)}</td><td>{s.get('lines_parsed', 0)}</td></tr>"
        for name, s in src.items()
    )
    parts.append("<h2>Processed Sources</h2>")
    parts.append(
        f"<table><tr><th>Source</th><th>Events</th><th>Lines parsed</th></tr>{src_rows}</table>"
    )

    limitations = "".join(f"<li>{item}</li>" for item in report.get("limitations", []))
    parts.append(
        f"<div class='foot'><b>Note:</b> {report.get('note', '')}<ul>{limitations}</ul></div>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def write_html(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(report), encoding="utf-8")
