from __future__ import annotations

from fastapi.testclient import TestClient
from skillcred.api import create_app


def _admin(monkeypatch) -> str:
    token = "root-admin-" + "A" * 48
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    return token


def test_register_client_issue_jwt_and_use_scoped_api(tmp_path, monkeypatch) -> None:
    admin = _admin(monkeypatch)
    client = TestClient(create_app(tmp_path))
    registered = client.post(
        "/admin/clients",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "Pilot issuer", "roles": ["issuer"]},
    )
    assert registered.status_code == 201, registered.text
    result = registered.json()
    assert result["status"] == "active"
    assert result["scopes"] == ["credential:issue"]
    issued = client.post(
        f"/admin/clients/{result['client_id']}/tokens",
        headers={"Authorization": f"Bearer {admin}"},
        json={"expires_in": 600},
    )
    assert issued.status_code == 200, issued.text
    token = issued.json()["access_token"]
    response = client.post(
        "/issue",
        headers={"Authorization": f"Bearer {token}"},
        json={"achievement_name": "Pilot skill"},
    )
    assert response.status_code == 200, response.text
    forbidden = client.post(
        "/revoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"status_list_index": 0},
    )
    assert forbidden.status_code == 403
    assert (tmp_path / "clients.enc").read_bytes().startswith(b"SCC1")
    assert b"Pilot issuer" not in (tmp_path / "clients.enc").read_bytes()


def test_client_registration_rejects_unknown_scope_and_admin_escalation(
    tmp_path, monkeypatch
) -> None:
    admin = _admin(monkeypatch)
    client = TestClient(create_app(tmp_path))
    headers = {"Authorization": f"Bearer {admin}"}
    bad_scope = client.post(
        "/admin/clients",
        headers=headers,
        json={"name": "Bad", "roles": ["issuer"], "scopes": ["credential:revoke"]},
    )
    assert bad_scope.status_code == 400
    bad_admin = client.post(
        "/admin/clients",
        headers=headers,
        json={"name": "Escalation", "roles": ["admin"]},
    )
    assert bad_admin.status_code == 400


def test_admin_list_does_not_expose_tokens_or_private_data(tmp_path, monkeypatch) -> None:
    admin = _admin(monkeypatch)
    client = TestClient(create_app(tmp_path))
    headers = {"Authorization": f"Bearer {admin}"}
    created = client.post(
        "/admin/clients", headers=headers, json={"name": "Inspect", "roles": ["verifier"]}
    )
    client_id = created.json()["client_id"]
    client.post(f"/admin/clients/{client_id}/tokens", headers=headers, json={"expires_in": 600})
    result = client.get("/admin/clients", headers=headers)
    assert result.status_code == 200
    assert result.json()["clients"][0]["client_id"] == client_id
    assert "access_token" not in result.text
    assert "private_key" not in result.text
