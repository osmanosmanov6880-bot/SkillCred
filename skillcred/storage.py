"""Encrypted local wallet storage and safe export helpers."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from skillcred.keys import private_key_from_base64, private_key_to_base64

_MAGIC = b"SCW1"
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


class WalletError(ValueError):
    """Raised for invalid, corrupted, or undecryptable wallet files."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise WalletError("Passphrase must not be empty")
    return Scrypt(salt=salt, length=_KEY_BYTES, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


def _atomic_write(path: Path, contents: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        with suppress(OSError):
            os.chmod(path, mode)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def save_wallet(path: str | Path, wallet: dict[str, Any], passphrase: str) -> Path:
    target = Path(path).expanduser().resolve()
    if "private_key" not in wallet or "issuer_name" not in wallet:
        raise WalletError("Wallet requires private_key and issuer_name")
    private_key_from_base64(str(wallet["private_key"]))  # Validate before storing.
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    payload = json.dumps(wallet, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, payload, _MAGIC)
    _atomic_write(target, _MAGIC + salt + nonce + ciphertext)
    return target


def load_wallet(path: str | Path, passphrase: str) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise WalletError(f"Could not read wallet: {source}") from exc
    min_length = len(_MAGIC) + _SALT_BYTES + _NONCE_BYTES + 16
    if len(raw) < min_length or raw[: len(_MAGIC)] != _MAGIC:
        raise WalletError("Wallet file has an unsupported format or is corrupted")
    offset = len(_MAGIC)
    salt = raw[offset : offset + _SALT_BYTES]
    offset += _SALT_BYTES
    nonce = raw[offset : offset + _NONCE_BYTES]
    ciphertext = raw[offset + _NONCE_BYTES :]
    try:
        plaintext = AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, ciphertext, _MAGIC)
        wallet = json.loads(plaintext)
    except (InvalidTag, ValueError, json.JSONDecodeError) as exc:
        raise WalletError(
            "Wallet could not be decrypted; wrong passphrase or damaged file"
        ) from exc
    if not isinstance(wallet, dict) or "private_key" not in wallet:
        raise WalletError("Decrypted wallet has an invalid structure")
    private_key_from_base64(str(wallet["private_key"]))
    return wallet


def export_wallet(source: str | Path, destination: str | Path) -> Path:
    """Copy an already-encrypted wallet; never exports plaintext key material."""
    src = Path(source).expanduser().resolve()
    dst = Path(destination).expanduser().resolve()
    if src == dst:
        raise WalletError("Source and destination wallet paths must differ")
    if not src.is_file():
        raise WalletError("Source wallet does not exist")
    raw = src.read_bytes()
    if not raw.startswith(_MAGIC):
        raise WalletError("Refusing to export a non-encrypted wallet")
    _atomic_write(dst, raw)
    return dst


def wallet_from_key(private_key: Any, issuer_name: str) -> dict[str, str]:
    """Construct serializable wallet data from an Ed25519 private key."""
    from skillcred.keys import identity_from_private_key

    identity = identity_from_private_key(private_key)
    return {
        "format": "skillcred-wallet-v1",
        "issuer_name": issuer_name.strip(),
        "issuer_id": identity.did,
        "verification_method": identity.verification_method,
        "private_key": private_key_to_base64(private_key),
    }
