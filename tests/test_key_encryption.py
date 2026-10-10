from __future__ import annotations

import os

import pytest
from skillcred.api import _load_or_create_signing_key
from skillcred.keys import identity_from_private_key
from skillcred.storage import WalletError


def test_api_key_is_stored_in_encrypted_wallet_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLCRED_PRIVATE_KEY_B64", raising=False)
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "long-test-passphrase-for-key-encryption")
    key, persistent = _load_or_create_signing_key(tmp_path)
    assert persistent is True
    wallet_file = tmp_path / "issuer-wallet.scw"
    assert wallet_file.exists()
    assert wallet_file.read_bytes().startswith(b"SCW1")
    assert not (tmp_path / "issuer-private-key.b64").exists()
    key2, persistent2 = _load_or_create_signing_key(tmp_path)
    assert persistent2 is True
    assert identity_from_private_key(key).did == identity_from_private_key(key2).did


def test_api_refuses_to_create_persistent_key_without_passphrase(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE_FILE", raising=False)
    with pytest.raises(RuntimeError, match="Configure SKILLCRED_KEY_PASSPHRASE"):
        _load_or_create_signing_key(tmp_path)


def test_api_rejects_short_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "too-short")
    with pytest.raises(RuntimeError, match="at least 12 characters"):
        _load_or_create_signing_key(tmp_path)


def test_api_rejects_short_passphrase_file(tmp_path, monkeypatch):
    secret = tmp_path / "secret.txt"
    secret.write_text("short", encoding="utf-8")
    if os.name != "nt":
        secret.chmod(0o600)
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE", raising=False)
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE_FILE", str(secret))
    with pytest.raises(RuntimeError, match="at least 12 characters"):
        _load_or_create_signing_key(tmp_path / "data")


def test_wrong_passphrase_cannot_load_encrypted_issuer_wallet(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "the-correct-long-passphrase")
    _load_or_create_signing_key(tmp_path)
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "a-different-wrong-passphrase")
    with pytest.raises(WalletError):
        _load_or_create_signing_key(tmp_path)


def test_passphrase_file_must_not_be_group_or_world_readable(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX permission bits are not meaningful on Windows")
    secret = tmp_path / "secret.txt"
    secret.write_text("long-passphrase-from-file", encoding="utf-8")
    secret.chmod(0o644)
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE", raising=False)
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE_FILE", str(secret))
    with pytest.raises(RuntimeError, match="must not be readable"):
        _load_or_create_signing_key(tmp_path / "data")


def test_legacy_plaintext_key_is_encrypted_then_removed(tmp_path, monkeypatch):
    from skillcred.keys import generate_keypair, private_key_to_base64

    old = tmp_path / "issuer-private-key.b64"
    old.write_text(private_key_to_base64(generate_keypair()), encoding="ascii")
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "migration-passphrase-long-enough")
    key, persistent = _load_or_create_signing_key(tmp_path)
    assert persistent
    assert identity_from_private_key(key).did
    assert (tmp_path / "issuer-wallet.scw").exists()
    assert not old.exists()


def test_legacy_key_migration_refuses_mismatch_with_existing_encrypted_wallet(
    tmp_path, monkeypatch
):
    from skillcred.keys import generate_keypair, private_key_to_base64
    from skillcred.storage import save_wallet, wallet_from_key

    passphrase = "migration-passphrase-long-enough"
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", passphrase)
    save_wallet(
        tmp_path / "issuer-wallet.scw", wallet_from_key(generate_keypair(), "Existing"), passphrase
    )
    (tmp_path / "issuer-private-key.b64").write_text(
        private_key_to_base64(generate_keypair()), encoding="ascii"
    )
    with pytest.raises(RuntimeError, match="differs from existing encrypted wallet"):
        _load_or_create_signing_key(tmp_path)
    assert (tmp_path / "issuer-private-key.b64").exists()
