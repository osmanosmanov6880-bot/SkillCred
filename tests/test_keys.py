from __future__ import annotations

import pytest

from skillcred.keys import (
    KeyFormatError,
    b58decode,
    b58encode,
    decode_multibase_ed25519,
    did_key,
    identity_from_private_key,
    private_key_from_base64,
    private_key_to_base64,
    generate_keypair,
)


def test_base58_round_trip_with_leading_zeroes() -> None:
    for value in (b"", b"\0\0a", bytes(range(256)), b"hello world"):
        assert b58decode(b58encode(value)) == value


def test_did_key_round_trip(private_key) -> None:
    identity = identity_from_private_key(private_key)
    recovered = decode_multibase_ed25519(identity.verification_method.rsplit("#", 1)[1])
    assert recovered.public_bytes_raw() == private_key.public_key().public_bytes_raw()
    assert identity.did == did_key(private_key.public_key())


def test_private_key_base64_round_trip() -> None:
    key = generate_keypair()
    recovered = private_key_from_base64(private_key_to_base64(key))
    assert recovered.public_key().public_bytes_raw() == key.public_key().public_bytes_raw()


def test_rejects_bad_multibase() -> None:
    with pytest.raises(KeyFormatError):
        decode_multibase_ed25519("not-a-key")


def test_rejects_bad_private_key_encodings() -> None:
    import pytest

    from skillcred.keys import private_key_from_base64

    with pytest.raises(KeyFormatError):
        private_key_from_base64("not base64!")
    with pytest.raises(KeyFormatError):
        private_key_from_base64("YQ==")


def test_rejects_invalid_base58_and_wrong_multicodec() -> None:
    import pytest

    with pytest.raises(KeyFormatError):
        b58decode("0OIl")
    # `z` + base58 for 32 zero bytes is not an Ed25519 Multikey because it lacks 0xed01.
    from skillcred.keys import b58encode

    with pytest.raises(KeyFormatError):
        decode_multibase_ed25519("z" + b58encode(bytes(34)))
