#!/usr/bin/env python3
"""Generate a privacy-aware summary report from SkillCred impact JSON export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def build_report(source: dict[str, Any]) -> dict[str, Any]:
    summary = source.get("summary")
    if not isinstance(summary, dict) or not isinstance(summary.get("records"), int):
        raise ValueError("Input does not contain a valid SkillCred impact summary")
    if not isinstance(summary.get("groups"), list):
        raise ValueError("Impact summary groups must be a list")
    return {
        "report_version": "1.0",
        "product": "SkillCred",
        "record_count": summary["records"],
        "privacy_minimum_group_size": summary.get("privacy_minimum_group_size", 3),
        "groups": summary["groups"],
        "limitations": [
            "Results are pilot observations and do not establish causal impact.",
            "Cost comparisons are only aggregated within the same declared currency.",
            "Groups smaller than the privacy threshold are omitted from summary metrics.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON export from GET /metrics/impact")
    parser.add_argument(
        "--output", type=Path, help="Write JSON report to this path; defaults to stdout"
    )
    args = parser.parse_args()
    try:
        source = json.loads(args.input.read_text(encoding="utf-8"))
        result = build_report(source)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"impact report failed: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
