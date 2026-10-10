from __future__ import annotations

import json

from fastapi.testclient import TestClient
from skillcred.api import create_app


def _tokens(monkeypatch):
    values = {
        "issuer": "issuer-token-" + "i" * 40,
        "revoker": "revoker-token-" + "r" * 40,
        "verifier": "verifier-token-" + "v" * 40,
        "admin": "admin-token-" + "a" * 40,
    }
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps(values))
    return values


def test_role_separation_issue_verify_revoke(tmp_path, monkeypatch):
    tokens = _tokens(monkeypatch)
    client = TestClient(create_app(tmp_path))
    body = {"achievement_name": "Skill", "achievement_description": "Test"}

    issue_as_verifier = client.post(
        "/issue", json=body, headers={"Authorization": f"Bearer {tokens['verifier']}"}
    )
    assert issue_as_verifier.status_code == 403
    issued = client.post(
        "/issue", json=body, headers={"Authorization": f"Bearer {tokens['issuer']}"}
    )
    assert issued.status_code == 200
    credential = issued.json()

    verify_as_issuer = client.post(
        "/verify",
        json={"credential": credential},
        headers={"Authorization": f"Bearer {tokens['issuer']}"},
    )
    assert verify_as_issuer.status_code == 403
    verify_as_verifier = client.post(
        "/verify",
        json={"credential": credential},
        headers={"Authorization": f"Bearer {tokens['verifier']}"},
    )
    assert verify_as_verifier.status_code == 200
    index = int(credential["credentialStatus"]["statusListIndex"])

    revoke_as_issuer = client.post(
        "/revoke",
        json={"status_list_index": index},
        headers={"Authorization": f"Bearer {tokens['issuer']}"},
    )
    assert revoke_as_issuer.status_code == 403
    revoke_as_revoker = client.post(
        "/revoke",
        json={"status_list_index": index},
        headers={"Authorization": f"Bearer {tokens['revoker']}"},
    )
    assert revoke_as_revoker.status_code == 200


def test_admin_has_all_roles_and_status_list_is_public(tmp_path, monkeypatch):
    tokens = _tokens(monkeypatch)
    client = TestClient(create_app(tmp_path))
    admin = {"Authorization": f"Bearer {tokens['admin']}"}
    issued = client.post("/issue", json={"achievement_name": "Skill"}, headers=admin)
    assert issued.status_code == 200
    assert (
        client.post("/verify", json={"credential": issued.json()}, headers=admin).status_code == 200
    )
    assert client.get("/status-list").status_code == 200


def test_invalid_role_config_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_API_TOKENS", json.dumps({"superuser": "q" * 40}))
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/issue",
        json={"achievement_name": "Skill"},
        headers={"Authorization": f"Bearer {'q' * 40}"},
    )
    assert response.status_code == 503
