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
    assert "<style>" in html and "severity_counts" not in html.replace("severity", "", 0)
    assert html.count("attack.mitre.org") > 0
    assert "<script" not in html.lower(), "no external scripts allowed"


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
