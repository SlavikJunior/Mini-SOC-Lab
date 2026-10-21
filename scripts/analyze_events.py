#!/usr/bin/env python3
"""Small heuristic analyzer for the synthetic JSONL events in this repository."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_INPUT = Path(__file__).resolve().parents[1] / "logs" / "sample_events.jsonl"


def load_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"Line {line_number} must contain a JSON object")
            events.append(event)
    return events


def analyze(events: list[dict[str, Any]], brute_force_threshold: int = 3) -> dict[str, Any]:
    failed_logons = [e for e in events if str(e.get("event_id")) == "4625"]
    counts = Counter(
        str(e["src_ip"]) for e in failed_logons
        if e.get("src_ip") not in (None, "", "-")
    )

    findings: list[dict[str, Any]] = []
    for ip, count in sorted(counts.items()):
        if count >= brute_force_threshold:
            related = [e for e in failed_logons if str(e.get("src_ip")) == ip]
            findings.append({
                "type": "repeated_failed_logons",
                "severity": "medium",
                "source_ip": ip,
                "count": count,
                "first_seen": min(str(e.get("timestamp", "")) for e in related),
                "last_seen": max(str(e.get("timestamp", "")) for e in related),
                "evidence": "Repeated Security Event ID 4625 from one source IP",
                "caveat": "Threshold is illustrative; confirm account, logon type, and environment context.",
            })

    for event in events:
        event_id = str(event.get("event_id"))
        image = str(event.get("image", "")).lower()
        command_line = str(event.get("command_line", "")).lower()
        if event_id in {"1", "4688"} and "powershell.exe" in image and (
            "-encodedcommand" in command_line or "-enc " in command_line
        ):
            findings.append({
                "type": "powershell_encoded_command",
                "severity": "medium",
                "timestamp": event.get("timestamp"),
                "host": event.get("host"),
                "user": event.get("user"),
                "image": event.get("image"),
                "parent_image": event.get("parent_image"),
                "evidence": "PowerShell process command line contains EncodedCommand switch",
                "caveat": "Encoded commands can be legitimate; inspect parent process and decoded content in a safe lab.",
            })

    return {
        "event_count": len(events),
        "failed_logon_count": len(failed_logons),
        "findings_count": len(findings),
        "findings": findings,
        "limitations": [
            "Works only with this project's simplified JSONL schema.",
            "Does not parse EVTX and is not a SIEM or Sigma execution engine.",
            "Findings are heuristics and require analyst validation.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Input JSONL file")
    parser.add_argument("--output", type=Path, help="Optional path for JSON report")
    parser.add_argument("--threshold", type=int, default=3, help="Failed-logon count threshold (default: 3)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    try:
        result = analyze(load_events(args.input), brute_force_threshold=args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
