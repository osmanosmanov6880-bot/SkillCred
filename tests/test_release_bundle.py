from __future__ import annotations

import tomllib
import zipfile

from scripts.create_release_bundle import create_bundle, excluded


def test_bundle_excludes_secrets_and_matches_markdown_inventory(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname="skillcred"\nversion="0.3.0"\n', encoding="utf-8"
    )
    (root / "README.md").write_text("# README\n", encoding="utf-8")
    (root / ".env.example").write_text("EXAMPLE=1\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (root / "issuer-wallet.scw").write_bytes(b"secret wallet")
    (root / "skillcred-data").mkdir()
    (root / "skillcred-data/status-state.json").write_text("{}", encoding="utf-8")
    zip_path, dump_path, names = create_bundle(root, tmp_path / "out")
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    with zipfile.ZipFile(zip_path) as archive:
        actual = {member.removeprefix(f"skillcred-{version}/") for member in archive.namelist()}
    dump = dump_path.read_text(encoding="utf-8")
    headings = {
        line.removeprefix("## `").removesuffix("`")
        for line in dump.splitlines()
        if line.startswith("## `")
    }
    assert actual == headings == set(names)
    assert ".env.example" in names
    assert ".env" not in names
    assert "issuer-wallet.scw" not in names
    assert "skillcred-data/status-state.json" not in names


def test_excluded_detects_private_state_names(tmp_path):
    root = tmp_path.resolve()
    assert excluded(root / "clients.enc", root)
    assert excluded(root / "certificate.pem", root)
    assert excluded(root / "any" / "__pycache__" / "module.pyc", root)
    assert excluded(root / "skillcred.egg-info" / "PKG-INFO", root)
