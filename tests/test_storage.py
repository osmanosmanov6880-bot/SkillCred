from __future__ import annotations

import os

import pytest
from skillcred.keys import generate_keypair
from skillcred.storage import WalletError, export_wallet, load_wallet, save_wallet, wallet_from_key

PASSPHRASE = "a-correct-horse-battery-42"


def test_encrypted_wallet_round_trip_and_permissions(tmp_path) -> None:
    wallet_path = tmp_path / "issuer.wallet"
    source = wallet_from_key(generate_keypair(), "Test Issuer")
    save_wallet(wallet_path, source, PASSPHRASE)
    assert wallet_path.read_bytes().startswith(b"SCW1")
    assert load_wallet(wallet_path, PASSPHRASE) == source
    if os.name == "posix":
        assert wallet_path.stat().st_mode & 0o077 == 0


def test_wallet_rejects_wrong_passphrase(tmp_path) -> None:
    path = tmp_path / "wallet"
    save_wallet(path, wallet_from_key(generate_keypair(), "Issuer"), PASSPHRASE)
    with pytest.raises(WalletError):
        load_wallet(path, "wrong-passphrase")


def test_wallet_corruption_is_detected(tmp_path) -> None:
    path = tmp_path / "wallet"
    save_wallet(path, wallet_from_key(generate_keypair(), "Issuer"), PASSPHRASE)
    content = bytearray(path.read_bytes())
    content[-1] ^= 0x01
    path.write_bytes(content)
    with pytest.raises(WalletError):
        load_wallet(path, PASSPHRASE)


def test_export_copies_ciphertext_only(tmp_path) -> None:
    source = tmp_path / "source.wallet"
    target = tmp_path / "exports" / "wallet-copy"
    save_wallet(source, wallet_from_key(generate_keypair(), "Issuer"), PASSPHRASE)
    export_wallet(source, target)
    assert source.read_bytes() == target.read_bytes()
    assert load_wallet(target, PASSPHRASE)["issuer_name"] == "Issuer"


def test_empty_passphrase_and_bad_wallet_are_rejected(tmp_path) -> None:
    path = tmp_path / "wallet"
    with pytest.raises(WalletError):
        save_wallet(path, wallet_from_key(generate_keypair(), "Issuer"), "")
    path.write_bytes(b"not-a-wallet")
    with pytest.raises(WalletError):
        load_wallet(path, PASSPHRASE)


def test_export_rejects_same_missing_or_plaintext_paths(tmp_path) -> None:
    source = tmp_path / "source.wallet"
    with pytest.raises(WalletError):
        export_wallet(source, tmp_path / "copy.wallet")
    source.write_bytes(b"plaintext private key")
    with pytest.raises(WalletError):
        export_wallet(source, tmp_path / "copy.wallet")
    with pytest.raises(WalletError):
        export_wallet(source, source)
