from __future__ import annotations

from fastapi.testclient import TestClient
from skillcred.api import create_app
from skillcred.federation import (
    FederationError,
    IssuerTrustStore,
    create_issuer_metadata,
    validate_issuer_metadata,
)
from skillcred.keys import generate_keypair, identity_from_private_key


def metadata():
    key = generate_keypair()
    identity = identity_from_private_key(key)
    return create_issuer_metadata(
        issuer_id=identity.did,
        name="External issuer",
        status_list_url="https://issuer.example.org/status-list",
    )


def test_discovery_metadata_is_explicitly_not_a_trust_assertion(tmp_path):
    app = create_app(tmp_path)
    response = TestClient(app).get("/.well-known/skillcred-issuer.json")
    assert response.status_code == 200
    body = response.json()
    assert body["id"].startswith("did:key:z")
    assert body["proofSuites"] == ["eddsa-jcs-2022"]
    assert body["discovery"]["trustImplied"] is False
    assert body["discovery"]["remoteFetchPerformed"] is False


def test_local_pin_requires_out_of_band_matching_did(tmp_path):
    store = IssuerTrustStore(tmp_path / "trusted-issuers.json")
    document = metadata()
    pinned = store.pin(document, document["id"], operator_note="Fingerprint verified by phone")
    assert pinned["id"] == document["id"]
    assert store.is_trusted(document["id"]) is True
    assert store.is_trusted("did:key:zNotPinned") is False
    assert "External issuer" in (tmp_path / "trusted-issuers.json").read_text()


def test_pin_rejects_did_mismatch_invalid_status_url_and_invalid_metadata(tmp_path):
    store = IssuerTrustStore(tmp_path / "pins.json")
    document = metadata()
    try:
        store.pin(document, "did:key:zSomeoneElse")
    except FederationError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("DID mismatch must not be trusted")
    malformed = {
        **document,
        "statusList": {"type": "BitstringStatusList", "url": "http://127.0.0.1.evil/status"},
    }
    assert any("HTTPS" in error for error in validate_issuer_metadata(malformed))
    assert validate_issuer_metadata({"id": "other"})


def test_pin_store_can_revoke_trust_and_persists(tmp_path):
    path = tmp_path / "pins.json"
    document = metadata()
    store = IssuerTrustStore(path)
    store.pin(document, document["id"])
    store.unpin(document["id"])
    assert not store.is_trusted(document["id"])
    assert store.list_pins() == []
    try:
        store.unpin(document["id"])
    except FederationError as exc:
        assert "not pinned" in str(exc)
    else:
        raise AssertionError("Unpinning unknown issuer must fail")


def test_admin_api_can_pin_and_unpin_issuer(tmp_path, monkeypatch):
    token = "federation-admin-" + "A" * 44
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    client = TestClient(create_app(tmp_path))
    issued_metadata = metadata()
    headers = {"Authorization": f"Bearer {token}"}
    pinned = client.post(
        "/admin/federation/pins",
        headers=headers,
        json={
            "metadata": issued_metadata,
            "expected_issuer_id": issued_metadata["id"],
            "operator_note": "Manual trust ceremony",
        },
    )
    assert pinned.status_code == 201, pinned.text
    assert (
        client.get("/admin/federation/pins", headers=headers).json()["issuers"][0]["id"]
        == issued_metadata["id"]
    )
    unpinned = client.delete(f"/admin/federation/pins/{issued_metadata['id']}", headers=headers)
    assert unpinned.status_code == 200
    assert client.get("/admin/federation/pins", headers=headers).json()["issuers"] == []


def test_federation_management_requires_admin(tmp_path, monkeypatch):
    token = "verify-only-token-" + "V" * 40
    monkeypatch.setenv("SKILLCRED_API_TOKENS", '{"verifier":"' + token + '"}')
    client = TestClient(create_app(tmp_path))
    assert (
        client.get(
            "/admin/federation/pins", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        == 403
    )
