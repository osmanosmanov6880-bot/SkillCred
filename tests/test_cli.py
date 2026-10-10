from __future__ import annotations

import json

from skillcred.cli import app
from typer.testing import CliRunner


def test_cli_init_issue_verify_export_info(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SKILLCRED_PASSWORD", "a-correct-horse-battery-42")
    runner = CliRunner()
    wallet = tmp_path / "issuer.wallet"
    result = runner.invoke(app, ["init", "--wallet", str(wallet), "--issuer-name", "CLI Test"])
    assert result.exit_code == 0, result.output
    credential_path = tmp_path / "credential.json"
    result = runner.invoke(
        app,
        [
            "issue",
            "--wallet",
            str(wallet),
            "--achievement",
            "CLI skill",
            "--description",
            "Passed",
            "--out",
            str(credential_path),
        ],
    )
    assert result.exit_code == 0, result.output
    credential = json.loads(credential_path.read_text())
    assert credential["proof"]["type"] == "DataIntegrityProof"
    result = runner.invoke(app, ["verify", str(credential_path)])
    assert result.exit_code == 0, result.output
    assert '"signature_valid": true' in result.output
    copy_path = tmp_path / "copy.wallet"
    result = runner.invoke(app, ["export", "--wallet", str(wallet), "--out", str(copy_path)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["info", "--wallet", str(wallet)])
    assert result.exit_code == 0, result.output
    assert "private_key" not in result.output


def test_cli_status_list_revoke_and_verify_status(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SKILLCRED_PASSWORD", "a-correct-horse-battery-42")
    runner = CliRunner()
    wallet = tmp_path / "issuer.wallet"
    assert runner.invoke(app, ["init", "--wallet", str(wallet)]).exit_code == 0
    state_dir = tmp_path / "state"
    list_url = "https://issuer.example/status-list"
    credential_path = tmp_path / "credential.json"
    issue = runner.invoke(
        app,
        [
            "issue",
            "--wallet",
            str(wallet),
            "--achievement",
            "Secure issue",
            "--description",
            "Tested",
            "--with-status",
            "--data-dir",
            str(state_dir),
            "--status-list-url",
            list_url,
            "--out",
            str(credential_path),
        ],
    )
    assert issue.exit_code == 0, issue.output
    status_path = tmp_path / "status-list.json"
    status_cmd = runner.invoke(
        app,
        [
            "status-list",
            "--wallet",
            str(wallet),
            "--data-dir",
            str(state_dir),
            "--url",
            list_url,
            "--out",
            str(status_path),
        ],
    )
    assert status_cmd.exit_code == 0, status_cmd.output
    verified = runner.invoke(
        app, ["verify", str(credential_path), "--status-list", str(status_path)]
    )
    assert verified.exit_code == 0, verified.output
    assert '"status": "active"' in verified.output
    revoke = runner.invoke(
        app,
        ["revoke", "0", "--wallet", str(wallet), "--data-dir", str(state_dir), "--url", list_url],
    )
    assert revoke.exit_code == 0, revoke.output
    runner.invoke(
        app,
        [
            "status-list",
            "--wallet",
            str(wallet),
            "--data-dir",
            str(state_dir),
            "--url",
            list_url,
            "--out",
            str(status_path),
        ],
    )
    revoked = runner.invoke(
        app, ["verify", str(credential_path), "--status-list", str(status_path)]
    )
    assert revoked.exit_code == 1
    assert '"status": "revoked"' in revoked.output


def test_cli_rejects_short_passphrase_and_existing_wallet(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setenv("SKILLCRED_PASSWORD", "short")
    result = runner.invoke(app, ["init", "--wallet", str(tmp_path / "wallet")])
    assert result.exit_code != 0
    monkeypatch.setenv("SKILLCRED_PASSWORD", "a-correct-horse-battery-42")
    wallet = tmp_path / "existing.wallet"
    assert runner.invoke(app, ["init", "--wallet", str(wallet)]).exit_code == 0
    result = runner.invoke(app, ["init", "--wallet", str(wallet)])
    assert result.exit_code != 0


def test_cli_info_rejects_wrong_passphrase(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setenv("SKILLCRED_PASSWORD", "a-correct-horse-battery-42")
    wallet = tmp_path / "wallet"
    assert runner.invoke(app, ["init", "--wallet", str(wallet)]).exit_code == 0
    monkeypatch.setenv("SKILLCRED_PASSWORD", "wrong-passphrase")
    result = runner.invoke(app, ["info", "--wallet", str(wallet)])
    assert result.exit_code != 0


def test_cli_credential_file_is_owner_only(tmp_path, monkeypatch) -> None:
    import os

    import pytest

    if os.name == "nt":
        pytest.skip("POSIX permission bits are not available on Windows")
    monkeypatch.setenv("SKILLCRED_PASSWORD", "a-correct-horse-battery-42")
    runner = CliRunner()
    wallet = tmp_path / "issuer.wallet"
    assert runner.invoke(app, ["init", "--wallet", str(wallet)]).exit_code == 0
    credential = tmp_path / "credential.json"
    issued = runner.invoke(
        app,
        [
            "issue",
            "--wallet",
            str(wallet),
            "--achievement",
            "Private skill",
            "--description",
            "Sensitive details",
            "--out",
            str(credential),
        ],
    )
    assert issued.exit_code == 0, issued.output
    assert (credential.stat().st_mode & 0o777) == 0o600
