from __future__ import annotations

import json
import zipfile
from pathlib import Path

from scripts.validate_release import validate


def _make_minimal_root(tmp_path: Path, version: str = "0.3.0") -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        f'[project]\nname="skillcred"\nversion="{version}"\n', encoding="utf-8"
    )
    (root / "skillcred").mkdir()
    (root / "skillcred/__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8"
    )
    for file in (
        "README.md", "SPEC.md", "SECURITY.md", "GOVERNANCE.md", "CHARTER.md",
        "CHARTER_AMENDMENTS.md", "CONTRIBUTOR_LADDER.md", "PENTEST_REPORT.md",
        "THREAT_MODEL.md", "VALIDATION_REPORT.md", "RELEASE_CHECKLIST.md", "RELEASE_SIGNING.md", "LICENSE",
        "skillcred/api.py", "skillcred/auth.py", "skillcred/client_registry.py",
        "skillcred/federation.py", "skillcred/jcs.py", "skillcred/impact.py",
        "skillcred/metrics.py", "skillcred/rate_limit.py", "skillcred/request_size.py",
        "tests/test_e2e.py", "tests/test_client_lifecycle.py", "tests/test_federation.py",
        "tests/test_owasp_api_top10.py", "1edtech/run.sh", "pilot/scenarios/university.md",
        "deploy/production/runbook.md", "tools/impact_report.py", "scripts/create_release_bundle.py",
        ".github/workflows/ci.yml", ".github/workflows/release.yml",
    ):
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("release validation fixture\n", encoding="utf-8")
    return root


def test_release_validator_accepts_version_consistent_source_tree(tmp_path: Path) -> None:
    result = validate(_make_minimal_root(tmp_path))
    assert result["status"] == "pass"
    assert result["errors"] == []


def test_release_validator_detects_version_mismatch(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    (root / "skillcred/__init__.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    result = validate(root)
    assert result["status"] == "fail"
    assert any("Version mismatch" in error for error in result["errors"])


def test_release_validator_detects_secret_file_in_source_tree(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    (root / "issuer-private-key.b64").write_text("not-a-real-key", encoding="utf-8")
    result = validate(root)
    assert result["status"] == "fail"
    assert any("issuer-private-key.b64" in error for error in result["errors"])


def test_release_validator_scans_zip_members_for_credentials(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    source_zip = tmp_path / "source.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("skillcred-0.3.0/README.md", "release")
        archive.writestr("skillcred-0.3.0/demo-output/issued-credential.json", json.dumps({"id": "x"}))
    result = validate(root, source_zip=source_zip)
    assert result["status"] == "fail"
    assert any("demo-output/issued-credential.json" in error for error in result["errors"])


def test_release_validator_compares_zip_and_markdown_file_lists(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    source_zip = tmp_path / "source.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("skillcred-0.3.0/README.md", "release")
    dump = tmp_path / "source.md"
    dump.write_text("# Source\n\n## `README.md`\n\n````text\nrelease\n````\n", encoding="utf-8")
    result = validate(root, source_zip=source_zip, source_dump=dump)
    assert result["status"] == "pass"


def test_release_validator_detects_zip_dump_file_list_mismatch(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    source_zip = tmp_path / "source.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("skillcred-0.3.0/README.md", "release")
        archive.writestr("skillcred-0.3.0/SPEC.md", "spec")
    dump = tmp_path / "source.md"
    dump.write_text("# Source\n\n## `README.md`\n", encoding="utf-8")
    result = validate(root, source_zip=source_zip, source_dump=dump)
    assert result["status"] == "fail"
    assert any("file mismatch" in error for error in result["errors"])


def test_release_validator_accepts_sdist_with_root_and_egg_info_metadata(tmp_path: Path) -> None:
    import tarfile
    import io

    root = _make_minimal_root(tmp_path)
    artifacts = tmp_path / "dist"
    artifacts.mkdir()
    sdist = artifacts / "skillcred-0.3.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in (
            ("skillcred-0.3.0/PKG-INFO", "Metadata-Version: 2.1\nVersion: 0.3.0\n"),
            ("skillcred-0.3.0/skillcred.egg-info/PKG-INFO", "Metadata-Version: 2.1\nVersion: 0.3.0\n"),
        ):
            info = tarfile.TarInfo(name)
            encoded = data.encode()
            info.size = len(encoded)
            archive.addfile(info, io.BytesIO(encoded))
    # The counterpart is enough to let the checker reach the sdist-metadata assertion.
    wheel = artifacts / "skillcred-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("skillcred-0.3.0.dist-info/METADATA", "Metadata-Version: 2.1\nVersion: 0.3.0\n")
    result = validate(root, artifact_dir=artifacts)
    assert result["status"] == "pass", result["errors"]


def test_release_validator_detects_private_key_material_in_archive(tmp_path: Path) -> None:
    root = _make_minimal_root(tmp_path)
    source_zip = tmp_path / "private.zip"
    marker = b"-----BEGIN " + b"PRIVATE KEY-----"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("skillcred-0.3.0/private.pem", marker + b"\nnot a real key\n")
    result = validate(root, source_zip=source_zip)
    assert result["status"] == "fail"
    assert any("private-key material marker" in error for error in result["errors"])
