from __future__ import annotations

from fastapi.testclient import TestClient
from skillcred.api import create_app


def test_api_issue_verify_and_revoke(tmp_path, monkeypatch) -> None:
    token = "pilot-secret-" + "x" * 40
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    headers = {"Authorization": f"Bearer {token}"}
    app = create_app(tmp_path)
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/issuer").json()["id"].startswith("did:key:")
    response = client.post(
        "/issue",
        json={
            "achievement_name": "Practical safety",
            "achievement_description": "Completed the skills assessment.",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    credential = response.json()
    status_list = client.get("/status-list").json()
    verified_response = client.post(
        "/verify",
        json={"credential": credential, "status_list_credential": status_list},
        headers=headers,
    )
    assert verified_response.status_code == 200
    verified = verified_response.json()
    assert verified["valid"] is True
    index = int(credential["credentialStatus"]["statusListIndex"])
    assert (
        client.post("/revoke", json={"status_list_index": index}, headers=headers).status_code
        == 200
    )
    revoked_list = client.get("/status-list").json()
    result_response = client.post(
        "/verify",
        json={"credential": credential, "status_list_credential": revoked_list},
        headers=headers,
    )
    assert result_response.status_code == 200
    result = result_response.json()
    assert result["signature_valid"] is True
    assert result["status"] == "revoked"
    assert result["valid"] is False
    bad_revoke = client.post("/revoke", json={"status_list_index": 131071}, headers=headers)
    assert bad_revoke.status_code == 400
    bad_issue = client.post(
        "/issue",
        json={"achievement_name": "   ", "achievement_description": "test"},
        headers=headers,
    )
    assert bad_issue.status_code == 422


def test_api_rejects_extra_fields(tmp_path) -> None:
    client = TestClient(create_app(tmp_path))
    response = client.post("/issue", json={"achievement_name": "x", "surprise": True})
    assert response.status_code == 422


def test_api_rejects_unsafe_evidence_urls_and_blank_subject_ids(tmp_path) -> None:
    client = TestClient(create_app(tmp_path))
    bad_url = client.post(
        "/issue",
        json={
            "achievement_name": "Skill",
            "evidence_url": "http://internal.example/private",
        },
    )
    assert bad_url.status_code == 422
    blank_subject = client.post(
        "/issue",
        json={"achievement_name": "Skill", "subject_id": "   "},
    )
    assert blank_subject.status_code == 422


def test_mutating_api_fails_closed_without_strong_configured_token(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    client = TestClient(create_app(tmp_path))
    payload = {"achievement_name": "Skill", "achievement_description": "Assessment"}
    assert client.post("/issue", json=payload).status_code == 503
    assert client.post("/revoke", json={"status_list_index": 0}).status_code == 503

    monkeypatch.setenv("SKILLCRED_API_TOKEN", "short")
    assert client.post("/issue", json=payload).status_code == 503


def test_mutating_api_requires_a_valid_bearer_token(tmp_path, monkeypatch) -> None:
    token = "pilot-secret-" + "z" * 40
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    client = TestClient(create_app(tmp_path))
    payload = {"achievement_name": "Skill", "achievement_description": "Assessment"}
    assert client.post("/issue", json=payload).status_code == 401
    assert (
        client.post("/issue", json=payload, headers={"Authorization": "Bearer wrong"}).status_code
        == 403
    )
    assert (
        client.post(
            "/issue", json=payload, headers={"Authorization": f"Bearer {token}"}
        ).status_code
        == 200
    )


def test_ephemeral_import_style_app_does_not_publish_a_status_list(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE_FILE", raising=False)
    app = create_app(tmp_path, allow_ephemeral=True)
    client = TestClient(app)
    assert client.get("/health").json()["signing_ready"] is False
    assert client.get("/ready").status_code == 503
    assert client.get("/status-list").status_code == 503

def test_public_homepage_serves_live_api_backed_product_page(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.delenv("SKILLCRED_ENABLE_API_DOCS", raising=False)
    client = TestClient(create_app(tmp_path))

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'lang="ru"' in response.text
    assert "Навыки принадлежат" in response.text
    assert 'id="issueBtn"' in response.text
    assert 'id="verifyBtn"' in response.text
    assert 'id="revokeBtn"' in response.text
    assert 'id="downloadBtn"' in response.text
    assert 'https://skillcred-pilot-api.onrender.com' in response.text
    assert "crypto.subtle.generateKey" not in response.text
    assert "DEMO_ISSUER_TOKEN" not in response.text
    assert "Экспериментальный пилот" in response.text


def test_public_homepage_and_api_docs_are_configured_separately(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("SKILLCRED_ENABLE_API_DOCS", "true")
    client = TestClient(create_app(tmp_path))

    response = client.get("/")

    assert response.status_code == 200
    assert 'href="https://skillcred-pilot-api.onrender.com/docs"' in response.text
    assert client.get("/docs").status_code == 200
    assert 'id="issueBtn"' in response.text


def test_public_demo_round_trip_persists_across_app_restart(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "test-encrypted-wallet-passphrase")
    monkeypatch.setenv("SKILLCRED_CLIENT_STORE_PASSPHRASE", "test-client-store-passphrase")
    monkeypatch.setenv("DEMO_ISSUER_TOKEN", "demo-enablement-secret-" + "d" * 40)
    first = TestClient(create_app(tmp_path))
    assert first.get("/ready").status_code == 200

    issued = first.post("/demo/issue")
    assert issued.status_code == 200, issued.text
    credential = issued.json()
    production_issuer = first.get("/issuer").json()["id"]
    assert credential["issuer"]["id"] != production_issuer
    demo_status_list = first.get("/demo/status-list")
    assert demo_status_list.status_code == 200
    assert demo_status_list.json()["issuer"]["id"] == credential["issuer"]["id"]
    assert credential["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert credential["credentialSubject"]["achievement"]["name"] == (
        "Practical safety — browser demo"
    )

    active = first.post("/demo/verify", json={"credential": credential})
    assert active.status_code == 200, active.text
    assert active.json()["signature_valid"] is True
    assert active.json()["valid"] is True
    assert active.json()["status"] == "active"

    # Recreate the ASGI app with the same persistent storage: the demo allowlist
    # and the signed status list must survive an application restart.
    second = TestClient(create_app(tmp_path))
    still_active = second.post("/demo/verify", json={"credential": credential})
    assert still_active.status_code == 200, still_active.text
    assert still_active.json()["valid"] is True

    revoked = second.post("/demo/revoke", json={"credential": credential})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked"] is True

    checked_again = second.post("/demo/verify", json={"credential": credential})
    assert checked_again.status_code == 200, checked_again.text
    result = checked_again.json()
    assert result["signature_valid"] is True
    assert result["valid"] is False
    assert result["status"] == "revoked"


def test_demo_api_allows_only_declared_browser_origin_cors(tmp_path) -> None:
    client = TestClient(create_app(tmp_path, allow_ephemeral=True))
    allowed = client.options(
        "/demo/issue",
        headers={
            "Origin": "https://osgard.world",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://osgard.world"

    denied = client.options(
        "/demo/issue",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert denied.headers.get("access-control-allow-origin") != "https://example.org"
