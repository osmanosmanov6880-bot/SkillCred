from __future__ import annotations

from fastapi.testclient import TestClient
from skillcred.api import create_app


def test_individual_token_and_whole_client_revocation(tmp_path, monkeypatch) -> None:
    admin = "root-admin-" + "V" * 48
    monkeypatch.setenv("SKILLCRED_API_TOKEN", admin)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    client = TestClient(create_app(tmp_path))
    root = {"Authorization": f"Bearer {admin}"}
    registered = client.post(
        "/admin/clients", headers=root, json={"name": "Verifier", "roles": ["verifier"]}
    ).json()
    client_id = registered["client_id"]
    token = client.post(
        f"/admin/clients/{client_id}/tokens", headers=root, json={"expires_in": 600}
    ).json()
    check = {"Authorization": f"Bearer {token['access_token']}"}
    assert client.post("/verify", headers=check, json={"credential": {}}).status_code == 200
    assert client.post(f"/admin/tokens/{token['jti']}/revoke", headers=root).status_code == 200
    assert client.post("/verify", headers=check, json={"credential": {}}).status_code == 403

    new_token = client.post(
        f"/admin/clients/{client_id}/tokens", headers=root, json={"expires_in": 600}
    ).json()
    assert client.post(f"/admin/clients/{client_id}/revoke", headers=root).status_code == 200
    assert (
        client.post(
            "/verify",
            headers={"Authorization": f"Bearer {new_token['access_token']}"},
            json={"credential": {}},
        ).status_code
        == 403
    )
