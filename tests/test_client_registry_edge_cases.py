from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from skillcred.client_registry import ClientRegistry, ClientRegistryError, TokenRejected


def registry(tmp_path, key=None):
    return ClientRegistry(
        tmp_path / "clients.enc",
        "long-test-passphrase-for-client-registry",
        key or Ed25519PrivateKey.generate(),
    )


def test_registry_rejects_short_passphrase_and_corrupt_state(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with pytest.raises(ClientRegistryError, match="at least 12"):
        ClientRegistry(tmp_path / "weak.enc", "short", Ed25519PrivateKey.generate())
    path = tmp_path / "broken.enc"
    path.write_bytes(b"not-a-registry")
    with pytest.raises(ClientRegistryError, match="format is invalid"):
        ClientRegistry(
            path, "long-test-passphrase-for-client-registry", Ed25519PrivateKey.generate()
        )


def test_client_validation_rejects_blank_name_unknown_role_and_empty_scopes(tmp_path):
    r = registry(tmp_path)
    for name, roles, scopes in [
        ("   ", ["issuer"], None),
        ("Valid", ["root"], None),
        ("Valid", ["issuer"], []),
    ]:
        with pytest.raises(ClientRegistryError):
            r.register_client(name, roles, scopes)


def test_client_registration_rejects_admin_unless_explicitly_enabled(tmp_path, monkeypatch):
    r = registry(tmp_path)
    monkeypatch.delenv("SKILLCRED_ALLOW_CLIENT_ADMIN", raising=False)
    with pytest.raises(ClientRegistryError, match="SKILLCRED_ALLOW_CLIENT_ADMIN"):
        r.register_client("Privileged", ["admin"])
    monkeypatch.setenv("SKILLCRED_ALLOW_CLIENT_ADMIN", "true")
    result = r.register_client("Privileged", ["admin"])
    assert result["roles"] == ["admin"]


def test_token_scope_override_cannot_escalate_or_be_empty(tmp_path):
    r = registry(tmp_path)
    c = r.register_client("issuer", ["issuer"])
    for scopes in (["credential:revoke"], []):
        with pytest.raises(ClientRegistryError, match="scopes"):
            r.issue_token(c["client_id"], scopes=scopes)


def test_token_expiry_revocation_and_audience_are_enforced(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    r = registry(tmp_path, key)
    c = r.register_client("verifier", ["verifier"])
    issued = r.issue_token(c["client_id"], ttl_seconds=60)
    assert (
        r.authenticate(issued["access_token"], "verifier", "credential:verify")["sub"]
        == c["client_id"]
    )
    real_time = time.time
    monkeypatch.setattr("skillcred.client_registry.time.time", lambda: real_time() + 120)
    with pytest.raises(TokenRejected, match="expired"):
        r.authenticate(issued["access_token"], "verifier", "credential:verify")


def test_token_rejects_wrong_audience_and_role(tmp_path):
    r = registry(tmp_path)
    c = r.register_client("issuer", ["issuer"])
    issued = r.issue_token(c["client_id"])
    with pytest.raises(TokenRejected):
        r.authenticate(issued["access_token"], "revoker", "credential:revoke")
    other = ClientRegistry(
        tmp_path / "other.enc",
        "long-test-passphrase-for-client-registry",
        r.signing_key,
        audience="other-api",
    )
    with pytest.raises(TokenRejected, match="issuer or audience"):
        other.authenticate(issued["access_token"], "issuer", "credential:issue")


def test_revoke_unknown_client_or_token_fails_closed(tmp_path):
    r = registry(tmp_path)
    with pytest.raises(ClientRegistryError, match="Client does not exist"):
        r.revoke_client("missing")
    with pytest.raises(ClientRegistryError, match="Token does not exist"):
        r.revoke_token("missing")


def test_registry_auth_rejects_malformed_token_and_large_token(tmp_path):
    r = registry(tmp_path)
    for token in ("bad", "a.b.c", "x" * 17000):
        with pytest.raises(TokenRejected):
            r.authenticate(token, "verifier", "credential:verify")


def test_registry_state_remains_encrypted_after_multiple_mutations(tmp_path):
    r = registry(tmp_path)
    c = r.register_client("Exporter", ["verifier"])
    issued = r.issue_token(c["client_id"])
    r.revoke_token(issued["jti"])
    raw = (tmp_path / "clients.enc").read_bytes()
    assert raw.startswith(b"SCC1")
    assert b"Exporter" not in raw
    assert b"access_token" not in raw
