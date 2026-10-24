"""Сборка отчёта из находок разных источников и рендеры JSON/HTML.

HTML-отчёт — самодостаточный дашборд: встроенные CSS/JS, переключатели
темы (тёмная/светлая) и языка интерфейса (EN/РУ). Внешних зависимостей нет.
"""
from __future__ import annotations

import html as html_mod
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

SEVERITY_BADGES = ("critical", "high", "medium", "low", "info")

# Цвета тактик MITRE (фиксированные, одинаковы в обеих темах)
TACTIC_COLORS: dict[str, str] = {
    "Initial Access": "#ff8a5d",
    "Execution": "#6db3f2",
    "Credential Access": "#ff5d5d",
    "Defense Evasion": "#ffb454",
    "Command and Control": "#b48aff",
    "Reconnaissance": "#ffd166",
    "Privilege Escalation": "#f472b6",
    "Discovery": "#38bdf8",
    "Impact": "#ef4444",
    "Exfiltration": "#a78bfa",
}

DETAIL_KEYS = (
    "source_ip", "src_ip", "count", "user", "image", "command_line", "path",
    "destination_ip", "target_users", "host", "process", "failed_count",
    "distinct_paths", "requests", "destination_port", "logon_type",
)


def _esc(value: Any) -> str:
    return html_mod.escape(str(value), quote=True)


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


# ---------------------------------------------------------------- HTML -------

CSS = """
  :root {
    --bg:#0e1520; --panel:#16202e; --panel2:#1b2736; --ink:#dbe4f0;
    --muted:#8b9bab; --border:#1d2838; --accent:#3ecfb2;
    --high:#ff5d5d; --medium:#ffb454; --low:#6db3f2; --info:#9aa7b6;
    --critical:#c81e5a;
  }
  [data-theme="light"] {
    --bg:#f4f6fa; --panel:#ffffff; --panel2:#eef2f7; --ink:#1d2733;
    --muted:#5b6b7c; --border:#dde5ee; --accent:#0f9d8a;
  }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); margin:0; padding:28px 32px 48px;
         font-family:-apple-system,'Segoe UI',Roboto,Ubuntu,sans-serif;
         font-size:14px; transition:background .25s,color .25s; }
  header { display:flex; align-items:flex-start; justify-content:space-between;
           gap:16px; flex-wrap:wrap; margin-bottom:22px; }
  h1 { font-size:21px; margin:0 0 4px; }
  .sub { color:var(--muted); font-size:12.5px; max-width:640px; line-height:1.55; }
  .switches { display:flex; gap:8px; align-items:center; }
  .sw-btn { background:var(--panel); border:1px solid var(--border); color:var(--ink);
            border-radius:8px; padding:6px 12px; font-size:12.5px; cursor:pointer;
            font-weight:600; }
  .sw-btn:hover { border-color:var(--accent); }
  .sw-btn.active { background:var(--accent); border-color:var(--accent); color:#08110f; }
  h2 { font-size:15px; margin:30px 0 12px; color:var(--accent);
       text-transform:uppercase; letter-spacing:.07em; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px;
          padding:14px 20px; min-width:118px; }
  .card .num { font-size:26px; font-weight:700; line-height:1.1; }
  .card .lbl { color:var(--muted); font-size:11px; text-transform:uppercase;
               letter-spacing:.07em; margin-top:3px; }
  .sev { display:inline-block; padding:2px 10px; border-radius:12px; font-weight:700;
         font-size:11px; text-transform:uppercase; color:#141a22; }
  .sev.critical { background:var(--critical); color:#fff; }
  .sev.high { background:var(--high); }
  .sev.medium { background:var(--medium); }
  .sev.low { background:var(--low); }
  .sev.info { background:var(--info); }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px;
           padding:16px 18px; }
  /* bar charts */
  .chart { display:flex; align-items:center; gap:12px; margin:7px 0; }
  .chart .lbl { width:90px; color:var(--muted); font-size:12.5px; text-transform:uppercase; }
  .track { flex:1; background:var(--panel2); border-radius:6px; height:20px;
           overflow:hidden; }
  .fill { height:100%; border-radius:6px; min-width:6px; }
  .fill.high { background:var(--high); } .fill.medium { background:var(--medium); }
  .fill.low { background:var(--low); } .fill.info { background:var(--info); }
  .fill.critical { background:var(--critical); }
  .fill.src { background:var(--accent); }
  .chart .val { width:34px; text-align:right; font-weight:700; font-variant-numeric:tabular-nums; }
  /* timeline */
  .timeline { position:relative; margin-left:6px; padding-left:22px;
              border-left:2px solid var(--border); }
  .tl-item { position:relative; padding:7px 0 7px 6px; display:flex; gap:12px;
             align-items:baseline; flex-wrap:wrap; }
  .tl-item::before { content:''; position:absolute; left:-29px; top:12px; width:10px;
                     height:10px; border-radius:50%; border:2px solid var(--bg); }
  .tl-item.high::before { background:var(--high); }
  .tl-item.medium::before { background:var(--medium); }
  .tl-item.low::before { background:var(--low); }
  .tl-item.info::before { background:var(--info); }
  .tl-item.critical::before { background:var(--critical); }
  .tl-time { color:var(--muted); font-variant-numeric:tabular-nums; font-size:12.5px; }
  .tl-src { font-weight:700; font-size:12.5px; }
  .tl-type code { font-size:12px; }
  /* tables */
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:12px; overflow:hidden;
          font-size:13px; }
  th { text-align:left; color:var(--muted); font-weight:600; padding:10px 14px;
       border-bottom:1px solid var(--border); font-size:11.5px;
       text-transform:uppercase; letter-spacing:.05em; }
  td { padding:10px 14px; border-bottom:1px solid var(--border); vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  code { color:var(--accent); font-size:12px; }
  details { margin-top:6px; }
  summary { cursor:pointer; color:var(--muted); font-size:12px; user-select:none; }
  summary:hover { color:var(--accent); }
  .det { color:var(--muted); font-size:12px; line-height:1.7; margin-top:6px; }
  a { color:var(--low); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .mitre-chips { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { background:var(--panel2); border:1px solid var(--border); border-radius:8px;
          padding:6px 10px; font-size:12.5px; }
  .chip .cnt { color:var(--muted); font-size:11px; }
  .tactic-head { display:flex; align-items:center; gap:8px; margin:14px 0 6px;
                 font-weight:700; font-size:13px; }
  .tactic-head .dot { width:10px; height:10px; border-radius:3px; display:inline-block; }
  .foot { color:var(--muted); font-size:12px; margin-top:30px; line-height:1.65;
          border-top:1px solid var(--border); padding-top:16px; }
"""

JS = """
(function () {
  'use strict';
  var I18N = {
    en: {
      doc_title: 'Mini SOC Lab — Analysis Report', title: 'Mini SOC Lab — Analysis Report',
      subtitle: 'Synthetic educational data · thresholds are illustrative · every finding needs analyst validation',
      h_events: 'Events', h_findings: 'Findings', h_critical: 'critical', h_high: 'high',
      h_medium: 'medium', h_low: 'low',
      h_by_severity: 'Findings by severity', h_by_source: 'Findings by source',
      h_timeline: 'Timeline', h_findings_tbl: 'Findings (sorted by severity)',
      h_coverage: 'MITRE ATT&CK Coverage', h_sources: 'Processed Sources',
      th_severity: 'Severity', th_time: 'Time', th_source: 'Source / Type',
      th_evidence: 'Evidence', th_mitre: 'MITRE ATT&CK',
      th_technique: 'Technique', th_tactic: 'Tactic', th_name: 'Name', th_count: 'Findings',
      th_src: 'Source', th_events: 'Events',
      note: 'Note:', lim1: 'Educational heuristics on synthetic data; not a SIEM and not a Sigma engine.',
      lim2: 'Thresholds are illustrative and tuned for the sample datasets.',
      lim3: 'Every finding requires analyst validation in context.',
      details: 'details'
    },
    ru: {
      doc_title: 'Mini SOC Lab — отчёт анализа', title: 'Mini SOC Lab — отчёт анализа',
      subtitle: 'Синтетические учебные данные · пороги иллюстративные · каждая находка требует проверки аналитиком',
      h_events: 'События', h_findings: 'Находки', h_critical: 'критич.', h_high: 'высокая',
      h_medium: 'средняя', h_low: 'низкая',
      h_by_severity: 'Находки по критичности', h_by_source: 'Находки по источникам',
      h_timeline: 'Хронология', h_findings_tbl: 'Находки (отсортированы по критичности)',
      h_coverage: 'Покрытие MITRE ATT&CK', h_sources: 'Обработанные источники',
      th_severity: 'Критичность', th_time: 'Время', th_source: 'Источник / тип',
      th_evidence: 'Обоснование', th_mitre: 'MITRE ATT&CK',
      th_technique: 'Техника', th_tactic: 'Тактика', th_name: 'Название', th_count: 'Находок',
      th_src: 'Источник', th_events: 'Событий',
      note: 'Примечание:', lim1: 'Учебные эвристики на синтетических данных; это не SIEM и не движок Sigma.',
      lim2: 'Пороги подобраны для демонстрационных наборов данных.',
      lim3: 'Каждая находка требует валидации аналитиком.',
      details: 'детали'
    }
  };

  function applyLang(lang) {
    var dict = I18N[lang] || I18N.en;
    document.documentElement.lang = lang;
    document.title = dict.doc_title;
    var nodes = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++) {
      var key = nodes[i].getAttribute('data-i18n');
      if (dict[key]) nodes[i].textContent = dict[key];
    }
    document.querySelectorAll('[data-lang-btn]').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-lang-btn') === lang);
    });
    try { localStorage.setItem('msl-lang', lang); } catch (e) { /* приватный режим */ }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.querySelector('[data-theme-btn]');
    if (btn) btn.textContent = theme === 'dark' ? '\\u2600 Light' : '\\u263C Dark';
    try { localStorage.setItem('msl-theme', theme); } catch (e) { /* приватный режим */ }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var theme = 'dark', lang = 'en';
    try {
      theme = localStorage.getItem('msl-theme') || 'dark';
      lang = localStorage.getItem('msl-lang') || 'en';
    } catch (e) { /* приватный режим */ }
    applyTheme(theme);
    applyLang(lang);
    var tbtn = document.querySelector('[data-theme-btn]');
    if (tbtn) tbtn.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') || 'dark';
      applyTheme(cur === 'dark' ? 'light' : 'dark');
    });
    document.querySelectorAll('[data-lang-btn]').forEach(function (b) {
      b.addEventListener('click', function () {
        applyLang(b.getAttribute('data-lang-btn'));
      });
    });
  });
})();
"""


def _bar(label: str, value: int, total: int, css_class: str) -> str:
    pct = round(value / total * 100) if total else 0
    return (
        f"<div class='chart'><div class='lbl'>{_esc(label)}</div>"
        f"<div class='track'><div class='fill {css_class}' style='width:{pct}%'></div></div>"
        f"<div class='val'>{value}</div></div>"
    )


def _severity_charts(counts: dict[str, Any], total: int) -> str:
    rows = "".join(
        _bar(sev, int(counts.get(sev, 0)), total, sev)
        for sev in ("critical", "high", "medium", "low", "info")
        if counts.get(sev)
    )
    return rows or "<div class='det'>no findings</div>"


def _source_charts(stats: dict[str, dict[str, int]], total: int) -> str:
    rows = "".join(
        _bar(name, int(s.get("findings", 0)), total, "src")
        for name, s in sorted(stats.items())
    )
    return rows or "<div class='det'>no findings</div>"


def _timeline(findings: list[dict[str, Any]]) -> str:
    chronological = sorted(
        findings,
        key=lambda d: str(d.get("first_seen") or d.get("timestamp") or ""),
    )
    items = "".join(
        "<div class='tl-item {sev}'>"
        "<span class='tl-time'>{time}</span>"
        "<span class='tl-src'>{src}</span>"
        "<span class='tl-type'><code>{typ}</code></span>"
        "</div>".format(
            sev=_esc(d.get("severity", "info")),
            time=_esc(str(d.get("first_seen") or d.get("timestamp") or "?")),
            src=_esc(d.get("source", "")),
            typ=_esc(d.get("type", "")),
        )
        for d in chronological
    )
    return f"<div class='timeline'>{items}</div>"


def _mitre_links(dct: dict[str, Any]) -> str:
    refs = dct.get("mitre", [])
    if not refs:
        return "—"
    return "<br>".join(
        f"<a href='https://attack.mitre.org/techniques/{_esc(m['technique_id']).replace('.', '/')}/' "
        f"target='_blank' rel='noopener'>{_esc(m['technique_id'])} {_esc(m['name'])}</a>"
        f" <span class='det'>({ _esc(m['tactic'])})</span>"
        for m in refs
    )


def _finding_row(dct: dict[str, Any]) -> str:
    severity = str(dct.get("severity", "info"))
    extras = "<br>".join(
        f"<code>{_esc(k)}: {_esc(dct[k])}</code>"
        for k in DETAIL_KEYS if k in dct and dct[k] not in (None, "")
    )
    details = (
        f"<details><summary data-i18n='details'>details</summary>"
        f"<div class='det'>{extras}</div></details>" if extras else ""
    )
    return (
        "<tr>"
        f"<td><span class='sev {severity}'>{severity}</span></td>"
        f"<td>{_esc(dct.get('first_seen') or '')}</td>"
        f"<td><b>{_esc(dct.get('source'))}</b><br><code>{_esc(dct.get('type'))}</code></td>"
        f"<td>{_esc(dct.get('evidence', ''))}{details}</td>"
        f"<td>{_mitre_links(dct)}</td>"
        "</tr>"
    )


def _mitre_coverage(coverage: list[dict[str, str]]) -> str:
    """Панель техник, сгруппированных по тактикам с цветными маркерами."""
    by_tactic: dict[str, list[dict[str, str]]] = {}
    for row in coverage:
        by_tactic.setdefault(row["tactic"], []).append(row)
    blocks: list[str] = []
    for tactic in sorted(by_tactic):
        color = TACTIC_COLORS.get(tactic, "var(--accent)")
        chips = "".join(
            "<span class='chip'>"
            f"<a href='https://attack.mitre.org/techniques/{_esc(r['technique_id']).replace('.', '/')}/' "
            f"target='_blank' rel='noopener'><code>{_esc(r['technique_id'])}</code> {_esc(r['name'])}</a> "
            f"<span class='cnt'>×{_esc(r['findings'])}</span>"
            "</span>"
            for r in by_tactic[tactic]
        )
        blocks.append(
            f"<div class='tactic-head'><span class='dot' style='background:{color}'></span>"
            f"{_esc(tactic)}</div><div class='mitre-chips'>{chips}</div>"
        )
    return "<div class='panel'>" + ("".join(blocks) or "<div class='det'>no coverage yet</div>") + "</div>"


HTML_HEAD = (
    "<!doctype html>\n<html lang='en' data-theme='dark'>\n<head>\n<meta charset='utf-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
    "<title>Mini SOC Lab — Analysis Report</title>\n"
    f"<style>{CSS}</style>\n</head>\n<body>\n"
    "<header>"
    "<div><h1 data-i18n='title'>Mini SOC Lab — Analysis Report</h1>"
    "<div class='sub' data-i18n='subtitle'>Synthetic educational data</div></div>"
    "<div class='switches'>"
    "<button class='sw-btn' data-theme-btn type='button'>&#9789; Light</button>"
    "<button class='sw-btn' data-lang-btn='en' type='button'>EN</button>"
    "<button class='sw-btn' data-lang-btn='ru' type='button'>РУ</button>"
    "</div></header>"
)


def render_html(report: dict[str, Any]) -> str:
    """Собрать самодостаточный HTML-отчёт (встроенные CSS/JS, без внешних зависимостей)."""
    parts: list[str] = [HTML_HEAD]
    counts = report.get("severity_counts", {})
    total = int(report.get("findings_count", 0)) or 1

    # KPI-карточки
    parts.append("<div class='cards'>")
    parts.append(
        f"<div class='card'><div class='num'>{report.get('event_count', 0)}</div>"
        "<div class='lbl' data-i18n='h_events'>Events</div></div>"
    )
    parts.append(
        f"<div class='card'><div class='num'>{report.get('findings_count', 0)}</div>"
        "<div class='lbl' data-i18n='h_findings'>Findings</div></div>"
    )
    for severity in ("critical", "high", "medium", "low"):
        parts.append(
            f"<div class='card'><div class='num' style='color:var(--{severity})'>"
            f"{counts.get(severity, 0)}</div>"
            f"<div class='lbl sev {severity}' data-i18n='h_{severity}'>{severity}</div></div>"
        )
    parts.append("</div>")

    # Графики
    parts.append("<div style='display:flex;gap:24px;flex-wrap:wrap;margin-top:22px'>")
    parts.append(
        "<div class='panel' style='flex:1;min-width:300px'>"
        "<h2 data-i18n='h_by_severity' style='margin-top:0'>Findings by severity</h2>"
        + _severity_charts(dict(counts), total) + "</div>"
    )
    parts.append(
        "<div class='panel' style='flex:1;min-width:300px'>"
        "<h2 data-i18n='h_by_source' style='margin-top:0'>Findings by source</h2>"
        + _source_charts(dict(report.get("sources", {})), total) + "</div>"
    )
    parts.append("</div>")

    # Timeline
    parts.append("<h2 data-i18n='h_timeline'>Timeline</h2>")
    parts.append(_timeline(list(report.get("findings", []))))

    # Таблица находок
    parts.append("<h2 data-i18n='h_findings_tbl'>Findings (sorted by severity)</h2>")
    parts.append(
        "<table><tr>"
        "<th data-i18n='th_severity'>Severity</th>"
        "<th data-i18n='th_time'>Time</th>"
        "<th data-i18n='th_source'>Source / Type</th>"
        "<th data-i18n='th_evidence'>Evidence</th>"
        "<th data-i18n='th_mitre'>MITRE ATT&amp;CK</th>"
        "</tr>"
    )
    for dct in report.get("findings", []):
        parts.append(_finding_row(dct))
    parts.append("</table>")

    # MITRE coverage
    parts.append("<h2 data-i18n='h_coverage'>MITRE ATT&amp;CK Coverage</h2>")
    parts.append(_mitre_coverage(list(report.get("mitre_coverage", []))))

    # Источники
    src = report.get("sources", {})
    src_rows = "".join(
        f"<tr><td><b>{_esc(name)}</b></td><td>{s.get('events', 0)}</td>"
        f"<td>{s.get('findings', 0)}</td></tr>"
        for name, s in sorted(src.items())
    )
    parts.append("<h2 data-i18n='h_sources'>Processed Sources</h2>")
    parts.append(
        "<table><tr>"
        "<th data-i18n='th_src'>Source</th>"
        "<th data-i18n='th_events'>Events</th>"
        "<th data-i18n='h_findings'>Findings</th>"
        f"</tr>{src_rows}</table>"
    )

    # Note и ограничения
    limitations = "".join(
        f"<li data-i18n='{key}'>{_esc(item)}</li>"
        for key, item in zip(("lim1", "lim2", "lim3"), report.get("limitations", []), strict=False)
    )
    parts.append(
        "<div class='foot'><b data-i18n='note'>Note:</b> "
        f"{_esc(report.get('note', ''))}<ul>{limitations}</ul></div>"
    )

    parts.append(f"<script>{JS}</script></body></html>")
    return "".join(parts)


def write_html(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(report), encoding="utf-8")
