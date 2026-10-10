from __future__ import annotations

from fastapi.testclient import TestClient

from skillcred.api import create_app


def test_rotation_invalidates_prior_tokens(tmp_path, monkeypatch) -> None:
    admin = "root-admin-" + "R" * 48
    monkeypatch.setenv("SKILLCRED_API_TOKEN", admin)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    client = TestClient(create_app(tmp_path))
    root = {"Authorization": f"Bearer {admin}"}
    registered = client.post("/admin/clients", headers=root, json={"name": "Issuer", "roles": ["issuer"]}).json()
    client_id = registered["client_id"]
    old = client.post(f"/admin/clients/{client_id}/tokens", headers=root, json={"expires_in": 600}).json()
    rotated = client.post(f"/admin/clients/{client_id}/rotate", headers=root, json={"expires_in": 600}).json()
    body = {"achievement_name": "Rotation check"}
    assert client.post("/issue", headers={"Authorization": f"Bearer {old['access_token']}"}, json=body).status_code == 403
    assert client.post("/issue", headers={"Authorization": f"Bearer {rotated['access_token']}"}, json=body).status_code == 200
    assert old["jti"] != rotated["jti"]
