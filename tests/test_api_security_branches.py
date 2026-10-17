from __future__ import annotations

import json

from fastapi.testclient import TestClient
from skillcred.api import create_app


def admin(monkeypatch):
    token = "admin-branch-token-" + "Q" * 40
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    return {"Authorization": f"Bearer {token}"}


def test_docs_are_disabled_by_default_and_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLCRED_ENABLE_API_DOCS", raising=False)
    client = TestClient(create_app(tmp_path / "off"))
    assert client.get("/docs").status_code == 404
    monkeypatch.setenv("SKILLCRED_ENABLE_API_DOCS", "true")
    enabled = TestClient(create_app(tmp_path / "on"))
    assert enabled.get("/openapi.json").status_code == 200


def test_client_admin_routes_require_admin_and_handle_bad_client(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps({"verifier": "v" * 48}))
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/admin/clients",
        headers={"Authorization": f"Bearer {'v' * 48}"},
        json={"name": "x", "roles": ["issuer"]},
    )
    assert response.status_code == 403
    headers = admin(monkeypatch)
    client = TestClient(create_app(tmp_path / "admin"))
    assert client.post("/admin/clients/missing/tokens", headers=headers, json={}).status_code == 400
    assert client.post("/admin/clients/missing/rotate", headers=headers, json={}).status_code == 400
    assert client.post("/admin/clients/missing/revoke", headers=headers).status_code == 400
    assert client.post("/admin/tokens/missing/revoke", headers=headers).status_code == 400


def test_impact_endpoint_requires_scope_and_admin_export(tmp_path, monkeypatch):
    admin_headers = admin(monkeypatch)
    monkeypatch.setenv(
        "SKILLCRED_API_TOKENS",
        json.dumps({"verifier": "v" * 48, "admin": admin_headers["Authorization"].split()[1]}),
    )
    client = TestClient(create_app(tmp_path))
    record = {
        "organization_ref": "org-pilot-001",
        "scenario": "university",
        "baseline_seconds": 100,
        "current_seconds": 60,
        "satisfaction": 4,
        "portability_passed": True,
        "consent_confirmed": True,
    }
    verifier = {"Authorization": f"Bearer {'v' * 48}"}
    assert client.post("/metrics/impact", headers=verifier, json=record).status_code == 201
    assert client.get("/metrics/impact", headers=verifier).status_code == 403
    assert client.get("/metrics/impact?format=weird", headers=admin_headers).status_code == 400
    csv_response = client.get("/metrics/impact?format=csv", headers=admin_headers)
    assert csv_response.status_code == 200 and "text/csv" in csv_response.headers["content-type"]


def test_rate_limit_configuration_invalid_fails_during_app_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_RATE_LIMITS_JSON", "not-json")
    client = TestClient(create_app(tmp_path))
    try:
        client.get("/health")
    except RuntimeError as exc:
        assert "SKILLCRED_RATE_LIMITS_JSON" in str(exc)
    else:
        raise AssertionError("malformed rate-limit configuration should fail closed")


def test_health_reports_release_version(tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.get("/health").json()["version"] == "0.3.0"


def test_credential_endpoints_reject_missing_authorization(tmp_path, monkeypatch):
    """Regression: unauthenticated callers cannot issue, verify or revoke."""
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps({
        "issuer": "i" * 48,
        "verifier": "v" * 48,
        "revoker": "r" * 48,
    }))
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    client = TestClient(create_app(tmp_path))
    cases = (
        ("/issue", {"achievement_name": "Safety", "achievement_description": "Practical test"}),
        ("/verify", {"credential": {}}),
        ("/revoke", {"status_list_index": 0}),
    )
    for path, body in cases:
        response = client.post(path, json=body)
        assert response.status_code in (401, 403), (path, response.status_code)


def test_credential_endpoints_enforce_separate_roles(tmp_path, monkeypatch):
    """Regression: a verifier must never acquire issuer/revoker privileges."""
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps({
        "issuer": "i" * 48,
        "verifier": "v" * 48,
        "revoker": "r" * 48,
    }))
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    client = TestClient(create_app(tmp_path))
    headers = {"Authorization": "Bearer " + "v" * 48}
    issue = client.post("/issue", headers=headers, json={
        "achievement_name": "Safety", "achievement_description": "Practical test"
    })
    revoke = client.post("/revoke", headers=headers, json={"status_list_index": 0})
    assert issue.status_code == 403
    assert revoke.status_code == 403
