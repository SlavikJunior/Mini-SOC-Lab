"""CLI: mini-soc-lab analyze [--format json|html] [--output PATH]."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from mini_soc_lab import __version__, detectors
from mini_soc_lab.loaders import load_source
from mini_soc_lab.report import build_report, render_html, write_html, write_json

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = PACKAGE_ROOT.parent

DEFAULT_SAMPLES: dict[str, Path] = {
    "windows": PROJECT_ROOT / "logs" / "windows_events.jsonl",
    "web": PROJECT_ROOT / "logs" / "web_access.log",
    "linux": PROJECT_ROOT / "logs" / "auth.log",
}

THRESHOLDS = {"windows": 3, "web": 10, "linux": 5}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mini-soc-lab",
        description="Учебный SOC-анализатор синтетических Windows/Linux/Web событий",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="проанализировать логи и собрать отчёт")
    for source, default_path in DEFAULT_SAMPLES.items():
        analyze.add_argument(f"--{source}", type=Path, default=default_path,
                             help=f"файл логов для источника '{source}'")
    analyze.add_argument("--only", choices=("windows", "web", "linux"),
                         help="анализировать только один источник")
    analyze.add_argument("--threshold", type=int, default=3,
                         help="порог для Windows brute force (по умолчанию 3)")
    analyze.add_argument("--format", choices=("json", "html"), default="json")
    analyze.add_argument("--output", type=Path, help="путь для сохранения отчёта")
    return parser


def analyze_sources(paths: dict[str, Path], threshold: int) -> dict[str, Any]:
    """Загрузить все выбранные источники, прогнать детекции, собрать отчёт."""
    stats: dict[str, dict[str, int]] = {}
    findings: list[Any] = []
    for source, path in paths.items():
        if not path.exists():
            raise OSError(f"sample file for source '{source}' not found: {path}")
        events = load_source(source, path)
        detector = getattr(detectors, source)
        source_findings = list(detector.detect_findings(events, threshold=threshold))
        stats[source] = {"events": len(events), "findings": len(source_findings)}
        findings.extend(source_findings)
    return build_report(findings, stats, threshold)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            only = getattr(args, "only", None)
            paths = {s: getattr(args, s) for s in DEFAULT_SAMPLES
                     if only is None or s == only}
            report = analyze_sources(paths, threshold=args.threshold)
            rendered: str
            if args.format == "html":
                rendered = render_html(report)
                if args.output:
                    write_html(report, args.output)
            else:
                import json
                rendered = json.dumps(report, indent=2, ensure_ascii=False)
                if args.output:
                    write_json(report, args.output)
            print(rendered)
            return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
