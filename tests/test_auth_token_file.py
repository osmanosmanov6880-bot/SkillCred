from __future__ import annotations

import json

from skillcred.auth import load_token_config, require_role


def test_loads_role_tokens_from_protected_file(tmp_path, monkeypatch):
    tokens = {role: f"{role}-" + role[0] * 48 for role in ("issuer", "revoker", "verifier", "admin")}
    secret = tmp_path / "tokens.json"
    secret.write_text(json.dumps(tokens), encoding="utf-8")
    secret.chmod(0o600)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    monkeypatch.setenv("SKILLCRED_API_TOKENS_FILE", str(secret))
    config = load_token_config()
    assert config.configured is True
    assert config.source == "role-map"
    assert require_role(f"Bearer {tokens['issuer']}", "issuer", config=config) == "issuer"



def test_loads_bootstrap_admin_token_from_protected_file(tmp_path, monkeypatch):
    secret = tmp_path / "bootstrap-admin"
    secret.write_text("bootstrap-admin-" + "z" * 48, encoding="utf-8")
    secret.chmod(0o600)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKENS_FILE", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    monkeypatch.setenv("SKILLCRED_API_TOKEN_FILE", str(secret))
    config = load_token_config()
    assert config.configured is True
    assert config.source == "legacy-admin-file"
    assert require_role("Bearer bootstrap-admin-" + "z" * 48, "admin", config=config) == "admin"


def test_bootstrap_token_file_rejects_permissive_permissions(tmp_path, monkeypatch):
    secret = tmp_path / "permissive"
    secret.write_text("bootstrap-admin-" + "z" * 48, encoding="utf-8")
    secret.chmod(0o644)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    monkeypatch.setenv("SKILLCRED_API_TOKEN_FILE", str(secret))
    try:
        load_token_config()
    except RuntimeError as exc:
        assert "not be readable" in str(exc)
    else:
        raise AssertionError("permissive bootstrap secret file should be rejected")
