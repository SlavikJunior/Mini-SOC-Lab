"""Интеграционные тесты: CLI, отчёты JSON/HTML, MITRE coverage."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

pkg = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(pkg))

from mini_soc_lab.cli import analyze_sources  # noqa: E402
from mini_soc_lab.report import render_html  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLES = {
    "windows": PROJECT_ROOT / "logs" / "windows_events.jsonl",
    "web": PROJECT_ROOT / "logs" / "web_access.log",
    "linux": PROJECT_ROOT / "logs" / "auth.log",
}


def full_report() -> dict[str, Any]:
    return analyze_sources(SAMPLES, threshold=3)


def test_report_has_findings_from_every_source() -> None:
    report = full_report()
    sources = {f["source"] for f in report["findings"]}
    assert sources == {"windows", "web", "linux"}


def test_report_structure_and_mitre_coverage() -> None:
    report = full_report()
    assert report["event_count"] > 50
    assert report["findings_count"] >= 10
    coverage = report["mitre_coverage"]
    assert coverage, "MITRE coverage must not be empty"
    assert all({"technique_id", "name", "tactic", "findings"} <= set(row) for row in coverage)


def test_findings_sorted_by_severity() -> None:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    report = full_report()
    severities = [order[str(f["severity"])] for f in report["findings"]]
    assert severities == sorted(severities)


def test_html_report_is_self_contained() -> None:
    html = render_html(full_report())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert html.count("attack.mitre.org") > 0
    assert "<script src" not in html.lower(), "no external scripts allowed"
    assert "https://cdn" not in html.lower(), "no CDN dependencies allowed"


def test_html_has_switchers_and_i18n() -> None:
    """Свитчеры темы/языка и словарь EN/RU встроены в отчёт."""
    html = render_html(full_report())
    assert "data-theme-btn" in html
    assert "data-lang-btn='en'" in html and "data-lang-btn='ru'" in html
    assert "data-theme" in html
    assert "localStorage" in html
    # словарь i18n содержит оба языка
    assert "I18N" in html and "ru:" in html and "en:" in html
    assert "Находки" in html and "Хронология" in html


def test_html_has_dashboard_structure() -> None:
    """Карточки, bar-charts, timeline, MITRE coverage по тактикам."""
    html = render_html(full_report())
    assert "class='cards'" in html
    assert "class='track'" in html and "class='fill high'" in html
    assert "class='timeline'" in html and "class='tl-item" in html
    assert "tactic-head" in html  # группировка coverage по тактикам
    assert "<details>" in html    # сворачиваемые детали находок
    assert "data-theme='dark'" in html  # тема по умолчанию


def test_html_escapes_finding_values() -> None:
    """Значения событий экранируются (защита от инъекций в отчёт)."""
    from mini_soc_lab.models import Finding
    evil = Finding(
        source="windows", kind="xss_test", severity="high",
        evidence="<script>alert(1)</script>",
        details={"command_line": "<img src=x onerror=alert(1)>"},
    )
    html = render_html(_mini_report([evil]))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def _mini_report(findings: list[Any]) -> dict[str, Any]:
    from mini_soc_lab.report import build_report
    return build_report(findings, {"windows": {"events": 1, "findings": 1}}, threshold=3)


def test_cli_test_and_tmp_outputs_are_clean(tmp_path: Path) -> None:
    report = analyze_sources(SAMPLES, threshold=3)
    out_json = tmp_path / "nested" / "report.json"
    from mini_soc_lab.report import write_html, write_json
    write_json(report, out_json)
    loaded = json.loads(out_json.read_text(encoding="utf-8"))
    assert loaded["findings_count"] == report["findings_count"]
    write_html(report, tmp_path / "report.html")
    assert (tmp_path / "report.html").stat().st_size > 4000


def test_cli_missing_source_file_errors(tmp_path: Path) -> None:
    from mini_soc_lab.cli import analyze_sources
    with pytest.raises(OSError):
        analyze_sources({"windows": tmp_path / "nope.jsonl"}, threshold=3)
