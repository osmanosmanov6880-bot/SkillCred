#!/usr/bin/env python3
"""Report local tooling needed for SkillCred validation without changing the host."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    checks: list[dict[str, object]] = []

    def add(name: str, available: bool, detail: str, required: bool = False) -> None:
        checks.append({"name": name, "available": available, "required": required, "detail": detail})

    add("Python", sys.version_info >= (3, 11), sys.version.split()[0] + " (requires >=3.11)", True)
    add("cryptography", importlib.util.find_spec("cryptography") is not None, "Ed25519/AES-GCM implementation", True)
    add("FastAPI", importlib.util.find_spec("fastapi") is not None, "HTTP API runtime", True)
    add("Pydantic", importlib.util.find_spec("pydantic") is not None, "request validation", True)
    add("prometheus-client", importlib.util.find_spec("prometheus_client") is not None, "Prometheus metrics", True)
    add("PyLD", importlib.util.find_spec("pyld") is not None, "python module pyld; required for the declared runtime profile", True)
    add("rfc8785", importlib.util.find_spec("rfc8785") is not None, "RFC 8785 implementation; required for complete number serialization", True)
    add("Typer", importlib.util.find_spec("typer") is not None, "CLI runtime", True)
    add("Uvicorn", importlib.util.find_spec("uvicorn") is not None, "ASGI server", True)
    add("ruff", shutil.which("ruff") is not None, shutil.which("ruff") or "not installed (development lint tool)")
    add("Docker", shutil.which("docker") is not None, shutil.which("docker") or "not installed (container validation unavailable)")
    suite_value = os.environ.get("SKILLCRED_1EDTECH_SUITE_DIR")
    suite = Path(suite_value).expanduser() if suite_value else None
    add(
        "1EdTech Open Badges suite",
        bool(suite and suite.is_dir()),
        str(suite) if suite and suite.is_dir() else "set SKILLCRED_1EDTECH_SUITE_DIR to a locally obtained official suite",
    )
    add("pytest", importlib.util.find_spec("pytest") is not None, "python module pytest", True)
    missing_required = any(c["required"] and not c["available"] for c in checks)
    missing_optional = any(not c["required"] and not c["available"] for c in checks)
    report = {
        "project": "SkillCred",
        "python": sys.version.split()[0],
        "status": "blocked" if missing_required else ("partial" if missing_optional else "complete"),
        "checks": checks,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if missing_required else 0


if __name__ == "__main__":
    raise SystemExit(main())
