"""Ed25519 key handling and did:key identifiers (Ed25519 multicodec)."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ED25519_PUB_MULTICODEC = bytes((0xED, 0x01))
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class KeyFormatError(ValueError):
    """Raised for malformed or unsupported key encodings."""


def b58encode(data: bytes) -> str:
    """Encode bytes using the Bitcoin base58 alphabet."""
    if not data:
        return ""
    zeroes = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = _BASE58_ALPHABET[remainder] + result
    return "1" * zeroes + result


def b58decode(value: str) -> bytes:
    """Decode Bitcoin base58, rejecting characters outside the alphabet."""
    if not value:
        return b""
    number = 0
    for character in value:
        try:
            digit = _BASE58_ALPHABET.index(character)
        except ValueError as exc:
            raise KeyFormatError("Invalid base58 character") from exc
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\0" * zeroes + body


def raw_private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_multibase(key: Ed25519PublicKey) -> str:
    """Return the `z` base58-btc Multikey encoding for an Ed25519 public key."""
    return "z" + b58encode(_ED25519_PUB_MULTICODEC + raw_public_bytes(key))


def did_key(key: Ed25519PublicKey) -> str:
    fingerprint = public_key_multibase(key)
    return f"did:key:{fingerprint}"


def verification_method(key: Ed25519PublicKey) -> str:
    identifier = did_key(key)
    return f"{identifier}#{identifier.removeprefix('did:key:')}"


def decode_multibase_ed25519(value: str) -> Ed25519PublicKey:
    """Decode a did:key fingerprint or Multikey fragment to an Ed25519 key."""
    if not value.startswith("z"):
        raise KeyFormatError("Only base58-btc multibase values (z...) are supported")
    decoded = b58decode(value[1:])
    if not decoded.startswith(_ED25519_PUB_MULTICODEC):
        raise KeyFormatError("Multibase key is not an Ed25519 public key")
    raw = decoded[len(_ED25519_PUB_MULTICODEC) :]
    if len(raw) != 32:
        raise KeyFormatError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_base64(key: Ed25519PrivateKey) -> str:
    """Encode raw private key bytes for use inside an encrypted wallet only."""
    return base64.b64encode(raw_private_bytes(key)).decode("ascii")


def private_key_from_base64(value: str) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32:
            raise KeyFormatError("Ed25519 private key must decode to 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        if isinstance(exc, KeyFormatError):
            raise
        raise KeyFormatError("Invalid base64 Ed25519 private key") from exc


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    if len(raw) != 32:
        raise KeyFormatError("Ed25519 private key must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


@dataclass(frozen=True)
class PublicIdentity:
    did: str
    verification_method: str
    public_key: Ed25519PublicKey


def identity_from_private_key(key: Ed25519PrivateKey) -> PublicIdentity:
    public = key.public_key()
    identifier = did_key(public)
    method = verification_method(public)
    return PublicIdentity(did=identifier, verification_method=method, public_key=public)
