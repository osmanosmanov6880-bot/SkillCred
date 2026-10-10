from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "script",
    ["scripts/run_1edtech_suite.sh", "deploy/verify_independent.sh"],
)
def test_shell_scripts_parse(script: str) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available on this platform")
    result = subprocess.run(
        [bash, "-n", str(ROOT / script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
