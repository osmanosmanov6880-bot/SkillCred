#!/usr/bin/env python3
"""Validate SkillCred source/release hygiene without contacting external services."""
from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

REQUIRED_FILES = (
    "README.md",
    "SPEC.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "CHARTER.md",
    "CHARTER_AMENDMENTS.md",
    "CONTRIBUTOR_LADDER.md",
    "THREAT_MODEL.md",
    "PENTEST_REPORT.md",
    "VALIDATION_REPORT.md",
    "RELEASE_CHECKLIST.md",
    "RELEASE_SIGNING.md",
    "LICENSE",
    "skillcred/api.py",
    "skillcred/auth.py",
    "skillcred/client_registry.py",
    "skillcred/federation.py",
    "skillcred/jcs.py",
    "skillcred/impact.py",
    "skillcred/metrics.py",
    "skillcred/rate_limit.py",
    "skillcred/request_size.py",
    "tests/test_e2e.py",
    "tests/test_client_lifecycle.py",
    "tests/test_federation.py",
    "tests/test_owasp_api_top10.py",
    "1edtech/run.sh",
    "pilot/scenarios/university.md",
    "deploy/production/runbook.md",
    "tools/impact_report.py",
    "scripts/create_release_bundle.py",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
)
SENSITIVE_PARTS = {
    "demo-output",
    "skillcred-data",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    ".git",
}
SENSITIVE_NAMES = {
    ".env",
    "status-state.json",
    "status-state.lock",
    "issuer-private-key.b64",
    "credential.json",
    "issued-credential.json",
    "tokens.json",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".wallet", ".scw", ".pyc", ".pyo"}
# Assemble markers from fragments so the release checker does not flag its own source.
SECRET_MARKERS = tuple(
    start + kind + end
    for start, kind, end in (
        (b"-----BEGIN ", b"PRIVATE KEY", b"-----"),
        (b"-----BEGIN ", b"OPENSSH PRIVATE KEY", b"-----"),
        (b"-----BEGIN ", b"RSA PRIVATE KEY", b"-----"),
    )
)
VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


def _is_sensitive_member(name: str) -> bool:
    path = PurePosixPath(name)
    parts = set(path.parts)
    if parts & SENSITIVE_PARTS:
        return True
    if path.name in SENSITIVE_NAMES:
        return True
    if path.name.startswith(".env") and path.name != ".env.example":
        return True
    if path.suffix.lower() in SENSITIVE_SUFFIXES:
        return True
    if "private-key" in path.name.lower() or "secret-token" in path.name.lower():
        return True
    return False


def _check_archive(path: Path, expected_version: str | None = None) -> list[str]:
    errors: list[str] = []
    if path.suffix == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
                if bad_member:
                    errors.append(f"{path.name}: corrupt ZIP member {bad_member}")
                for member in archive.namelist():
                    if _is_sensitive_member(member):
                        errors.append(f"{path.name}: sensitive/generated member {member}")
                    if not member.endswith("/"):
                        payload = archive.read(member)
                        if any(marker in payload for marker in SECRET_MARKERS):
                            errors.append(f"{path.name}: private-key material marker in {member}")
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(f"{path.name}: cannot read ZIP: {exc}")
    elif path.name.endswith((".tar.gz", ".tgz")):
        try:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                for member in members:
                    if _is_sensitive_member(member.name):
                        errors.append(f"{path.name}: sensitive/generated member {member.name}")
                    if member.isfile():
                        stream = archive.extractfile(member)
                        payload = stream.read() if stream else b""
                        if any(marker in payload for marker in SECRET_MARKERS):
                            errors.append(f"{path.name}: private-key material marker in {member.name}")
                pkg_infos = [
                    m for m in members
                    if m.name.endswith('/PKG-INFO')
                    and len(PurePosixPath(m.name).parts) == 2
                ]
                if expected_version and len(pkg_infos) != 1:
                    errors.append(f"{path.name}: expected exactly one PKG-INFO file")
                for member in pkg_infos:
                    stream = archive.extractfile(member)
                    metadata_text = stream.read().decode('utf-8', errors='replace') if stream else ''
                    if expected_version and f"Version: {expected_version}" not in metadata_text:
                        errors.append(f"{path.name}: source metadata version mismatch")
        except (OSError, tarfile.TarError) as exc:
            errors.append(f"{path.name}: cannot read tarball: {exc}")
    elif path.suffix == ".whl":
        try:
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
                if bad_member:
                    errors.append(f"{path.name}: corrupt wheel member {bad_member}")
                names = archive.namelist()
                for member in names:
                    # Wheels need dist-info metadata, but never real secrets.
                    if _is_sensitive_member(member):
                        errors.append(f"{path.name}: sensitive member {member}")
                    if any(marker in archive.read(member) for marker in SECRET_MARKERS):
                        errors.append(f"{path.name}: private-key material marker in {member}")
                metadata_names = [n for n in names if n.endswith('.dist-info/METADATA')]
                if expected_version and len(metadata_names) != 1:
                    errors.append(f"{path.name}: expected exactly one wheel METADATA file")
                for metadata_name in metadata_names:
                    metadata_text = archive.read(metadata_name).decode('utf-8', errors='replace')
                    if expected_version and f"Version: {expected_version}" not in metadata_text:
                        errors.append(f"{path.name}: wheel metadata version mismatch")
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(f"{path.name}: cannot read wheel: {exc}")
    return errors


def validate(
    root: Path,
    artifact_dir: Path | None = None,
    source_zip: Path | None = None,
    source_dump: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    root = root.resolve()
    try:
        with (root / "pyproject.toml").open("rb") as handle:
            metadata = tomllib.load(handle)
        project_version = metadata["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        return {"status": "fail", "errors": [f"Cannot read project metadata: {exc}"], "warnings": []}

    try:
        init_text = (root / "skillcred/__init__.py").read_text(encoding="utf-8")
        match = VERSION_RE.search(init_text)
        if not match:
            errors.append("skillcred/__init__.py has no literal __version__")
        elif match.group(1) != project_version:
            errors.append(f"Version mismatch: pyproject={project_version}, package={match.group(1)}")
    except OSError as exc:
        errors.append(f"Cannot read package version: {exc}")

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append(f"Required file missing: {relative}")

    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        rel = candidate.relative_to(root).as_posix()
        if _is_sensitive_member(rel):
            # Generated local state may exist in a developer's working tree;
            # it is excluded from release archives by packaging rules.
            if any(part in SENSITIVE_PARTS for part in PurePosixPath(rel).parts):
                continue
            errors.append(f"Potential secret/credential in source tree: {rel}")
        elif candidate.is_file() and candidate.suffix.lower() in {".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".conf", ".hcl"}:
            try:
                payload = candidate.read_bytes()
            except OSError:
                payload = b""
            if any(marker in payload for marker in SECRET_MARKERS):
                errors.append(f"Private-key material marker found in source file: {rel}")

    if artifact_dir is not None:
        artifact_dir = artifact_dir.resolve()
        expected = {
            f"skillcred-{project_version}-py3-none-any.whl",
            f"skillcred-{project_version}.tar.gz",
        }
        present = {p.name for p in artifact_dir.glob("*") if p.is_file()}
        for name in sorted(expected - present):
            errors.append(f"Distribution artifact missing: {artifact_dir / name}")
        for path in sorted(artifact_dir.glob("*")):
            if path.is_file() and path.suffix in {".whl", ".gz", ".zip"}:
                errors.extend(_check_archive(path, expected_version=project_version))

    if source_zip is not None:
        source_zip = source_zip.resolve()
        errors.extend(_check_archive(source_zip, expected_version=project_version))

    if source_zip is not None and source_dump is not None:
        try:
            with zipfile.ZipFile(source_zip) as archive:
                zip_paths = {
                    PurePosixPath(name).relative_to(PurePosixPath('skillcred-' + project_version)).as_posix()
                    for name in archive.namelist()
                    if not name.endswith('/')
                }
            dump_text = source_dump.read_text(encoding='utf-8')
            dump_paths = set(re.findall(r'^## `([^`]+)`$', dump_text, re.MULTILINE))
            if zip_paths != dump_paths:
                errors.append(
                    f"Source ZIP/source dump file mismatch: ZIP-only={sorted(zip_paths - dump_paths)[:5]}, "
                    f"dump-only={sorted(dump_paths - zip_paths)[:5]}"
                )
        except (OSError, zipfile.BadZipFile, ValueError) as exc:
            errors.append(f"Could not compare source ZIP and source dump: {exc}")

    if not errors:
        status = "pass"
    else:
        status = "fail"
    return {
        "project": "SkillCred",
        "version": project_version,
        "status": status,
        "required_files": len(REQUIRED_FILES),
        "artifact_dir": str(artifact_dir) if artifact_dir else None,
        "source_zip": str(source_zip.resolve()) if source_zip else None,
        "source_dump": str(source_dump.resolve()) if source_dump else None,
        "errors": errors,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifact-dir", type=Path, default=None, help="Directory containing wheel and sdist")
    parser.add_argument("--source-zip", type=Path, default=None, help="Optional source ZIP to scan for sensitive files")
    parser.add_argument("--source-dump", type=Path, default=None, help="Optional Markdown dump to compare with --source-zip")
    args = parser.parse_args()
    result = validate(args.root, args.artifact_dir, args.source_zip, args.source_dump)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
