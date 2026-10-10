"""Regression controls mapped to OWASP API Security Top 10 (2023).

These tests are targeted regression checks, not a claim that an independent pentest
or complete ASVS assessment has been performed.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from skillcred.api import create_app


def _configured(monkeypatch, tmp_path, **kwargs):
    tokens = {role: f"owasp-{role}-" + role[0].upper() * 42 for role in ("issuer", "revoker", "verifier", "admin")}
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps(tokens))
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    return TestClient(create_app(tmp_path, **kwargs)), tokens


def test_api1_object_and_client_ids_do_not_grant_cross_client_admin_access(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path)
    result = client.post("/admin/clients", headers={"Authorization": f"Bearer {tokens['issuer']}"}, json={"name": "attempt", "roles": ["verifier"]})
    assert result.status_code == 403


def test_api2_invalid_bearer_token_is_rejected(tmp_path, monkeypatch):
    client, _ = _configured(monkeypatch, tmp_path)
    result = client.post("/issue", headers={"Authorization": "Bearer not-a-real-token"}, json={"achievement_name": "Test"})
    assert result.status_code == 403


def test_api3_mass_assignment_fields_are_rejected(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path)
    result = client.post("/issue", headers={"Authorization": f"Bearer {tokens['issuer']}"}, json={"achievement_name": "Skill", "issuer": "attacker", "status": "valid"})
    assert result.status_code == 422


def test_api4_rate_and_payload_limits_exist(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path, rate_limit=2, rate_window_seconds=60)
    headers = {"Authorization": f"Bearer {tokens['issuer']}"}
    client.get("/issuer")
    client.get("/issuer")
    assert client.get("/issuer").status_code == 429
    oversized = client.post("/issue", content=b"x" * (1024 * 1024 + 1), headers={**headers, "Content-Type": "application/json"})
    assert oversized.status_code == 413


def test_api5_function_level_authorization_is_separated(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path)
    result = client.post("/issue", headers={"Authorization": f"Bearer {tokens['verifier']}"}, json={"achievement_name": "Skill"})
    assert result.status_code == 403


def test_api6_sensitive_issue_flow_hits_endpoint_limit(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path, rate_limit=1, rate_window_seconds=60)
    headers = {"Authorization": f"Bearer {tokens['issuer']}"}
    assert client.post("/issue", headers=headers, json={"achievement_name": "One"}).status_code == 200
    assert client.post("/issue", headers=headers, json={"achievement_name": "Two"}).status_code == 429


def test_api7_ssrf_style_internal_http_evidence_is_rejected(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path)
    result = client.post("/issue", headers={"Authorization": f"Bearer {tokens['issuer']}"}, json={"achievement_name": "Skill", "evidence_url": "http://169.254.169.254/latest/meta-data/"})
    assert result.status_code == 422


def test_api8_unconfigured_ephemeral_key_is_not_ready(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("SKILLCRED_PRIVATE_KEY_B64", raising=False)
    client = TestClient(create_app(tmp_path, allow_ephemeral=True))
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 503


def test_api9_unknown_legacy_route_is_not_silently_enabled(tmp_path, monkeypatch):
    client, _ = _configured(monkeypatch, tmp_path)
    assert client.get("/api/v1/issue").status_code == 404


def test_api10_malformed_external_payload_is_handled_as_invalid_not_server_error(tmp_path, monkeypatch):
    client, tokens = _configured(monkeypatch, tmp_path)
    result = client.post("/verify", headers={"Authorization": f"Bearer {tokens['verifier']}"}, json={"credential": {"not": "a credential"}})
    assert result.status_code == 200
    assert result.json().get("valid") is False
