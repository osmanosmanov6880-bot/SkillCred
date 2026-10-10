from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_check_env_script_emits_machine_readable_report():
    root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/check_env.py"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode in {0, 1}, result.stdout + result.stderr
    report = json.loads(result.stdout)
    names = {item["name"] for item in report["checks"]}
    assert {
        "ruff",
        "Docker",
        "PyLD",
        "rfc8785",
        "1EdTech Open Badges suite",
        "prometheus-client",
    }.issubset(names)
