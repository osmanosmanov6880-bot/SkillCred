from __future__ import annotations

import pytest

from skillcred.badge import create_credential
from skillcred.statuslist import (
    StatusListError,
    StatusListManager,
    check_credential_status,
    create_status_entry,
    decode_list,
    encode_list,
    is_set,
    set_bit,
)
from skillcred.verify import verify_credential, verify_signature


def test_status_bits_round_trip() -> None:
    bits = bytearray(131072 // 8)
    set_bit(bits, 0)
    set_bit(bits, 7)
    set_bit(bits, 8)
    encoded = encode_list(bits)
    recovered = decode_list(encoded)
    assert recovered[0] == 0b10000001
    assert is_set(recovered, 0)
    assert is_set(recovered, 7)
    assert is_set(recovered, 8)
    assert not is_set(recovered, 9)


def test_index_bounds_are_checked() -> None:
    with pytest.raises(StatusListError):
        create_status_entry("https://issuer.example/status-list", 131072)
    with pytest.raises(StatusListError):
        is_set(bytearray(1), 8)


def test_active_then_revoked_status(tmp_path, private_key) -> None:
    url = "https://issuer.example/status-list"
    manager = StatusListManager(tmp_path, private_key, "Issuer", url)
    entry = manager.allocate()
    credential = create_credential(
        private_key,
        issuer_name="Issuer",
        achievement_name="Skill",
        achievement_description="Test",
        credential_status=entry,
    )
    active_list = manager.create_credential()
    assert verify_signature(active_list)
    assert check_credential_status(credential, active_list) == "active"
    assert verify_credential(credential, status_list_credential=active_list)["valid"]

    manager.revoke(0)
    revoked_list = manager.create_credential()
    assert check_credential_status(credential, revoked_list) == "revoked"
    result = verify_credential(credential, status_list_credential=revoked_list)
    assert result["signature_valid"] is True
    assert result["valid"] is False
    assert "revoked" in " ".join(result["errors"]).lower()


def test_cannot_revoke_unallocated_index(tmp_path, private_key) -> None:
    manager = StatusListManager(
        tmp_path, private_key, "Issuer", "https://issuer.example/status-list"
    )
    with pytest.raises(StatusListError):
        manager.revoke(0)


def test_status_list_rejects_bad_urls_and_invalid_encoded_data(private_key) -> None:
    from skillcred.statuslist import create_status_list_credential

    with pytest.raises(StatusListError):
        create_status_list_credential(
            private_key,
            issuer_name="Issuer",
            status_list_url="http://external.example/list",
            revoked_indices=set(),
        )
    with pytest.raises(StatusListError):
        encode_list(bytearray(4))
    with pytest.raises(StatusListError):
        decode_list("Zm9v")
    with pytest.raises(StatusListError):
        decode_list("uZm9v")


def test_status_list_rejects_bad_status_entries(tmp_path, private_key) -> None:
    manager = StatusListManager(
        tmp_path / "state",
        private_key,
        "Issuer",
        "https://issuer.example/status-list",
    )
    entry = manager.allocate()
    credential = {
        "issuer": {"id": manager.create_credential()["issuer"]["id"]},
        "credentialStatus": dict(entry),
    }
    status_list = manager.create_credential()
    cases = []
    wrong_type = dict(entry)
    wrong_type["type"] = "WrongType"
    cases.append(wrong_type)
    wrong_purpose = dict(entry)
    wrong_purpose["statusPurpose"] = "suspension"
    cases.append(wrong_purpose)
    wrong_index_type = dict(entry)
    wrong_index_type["statusListIndex"] = 0
    cases.append(wrong_index_type)
    leading_zero = dict(entry)
    leading_zero["statusListIndex"] = "00"
    cases.append(leading_zero)
    wrong_id = dict(entry)
    wrong_id["id"] = "https://issuer.example/status-list#9"
    cases.append(wrong_id)
    for candidate in cases:
        broken = dict(credential)
        broken["credentialStatus"] = candidate
        with pytest.raises(StatusListError):
            check_credential_status(broken, status_list)


def test_status_state_corruption_and_multi_manager_indices(tmp_path, private_key) -> None:
    state_dir = tmp_path / "state"
    url = "https://issuer.example/status-list"
    first = StatusListManager(state_dir, private_key, "Issuer", url)
    second = StatusListManager(state_dir, private_key, "Issuer", url)
    assert first.allocate()["statusListIndex"] == "0"
    assert second.allocate()["statusListIndex"] == "1"
    state_file = state_dir / "status-state.json"
    state_file.write_text('{"version":99,"next_index":0,"revoked_indices":[]}', encoding="utf-8")
    with pytest.raises(StatusListError):
        first.allocate()


def test_status_list_url_validation_rejects_credentialed_and_fragment_urls(
    tmp_path, private_key
) -> None:
    with pytest.raises(StatusListError):
        StatusListManager(
            tmp_path / "state1", private_key, "Issuer", "https://user:pass@example.org/list"
        )
    with pytest.raises(StatusListError):
        StatusListManager(
            tmp_path / "state2", private_key, "Issuer", "https://example.org/list#fragment"
        )

def test_status_state_file_has_owner_only_permissions(tmp_path, private_key) -> None:
    import os

    if os.name == "nt":
        pytest.skip("POSIX permission bits are not available on Windows")
    manager = StatusListManager(
        tmp_path, private_key, "Issuer", "https://issuer.example/status-list"
    )
    manager.allocate()
    assert (manager.state_path.stat().st_mode & 0o777) == 0o600


def test_status_state_is_bound_to_key_and_url(tmp_path, private_key) -> None:
    from skillcred.keys import generate_keypair

    state_dir = tmp_path / "state"
    url = "https://issuer.example/status-list"
    manager = StatusListManager(state_dir, private_key, "Issuer", url)
    manager.allocate()
    with pytest.raises(StatusListError, match="different issuer key"):
        StatusListManager(state_dir, generate_keypair(), "Issuer", url)
    with pytest.raises(StatusListError, match="different status-list URL"):
        StatusListManager(state_dir, private_key, "Issuer", "https://issuer.example/other-list")


def test_status_list_rejects_invalid_multibase_and_compression() -> None:
    from skillcred.statuslist import _base64url

    with pytest.raises(StatusListError, match="invalid base64url characters"):
        decode_list("u@@@")
    with pytest.raises(StatusListError, match="valid gzip"):
        decode_list(_base64url(b"not-gzip"))
    with pytest.raises(StatusListError, match="unexpectedly large"):
        decode_list("u" + "A" * (24 * 1024 * 1024 + 1))


def test_status_bit_can_be_cleared_and_url_must_be_absolute(private_key, tmp_path) -> None:
    bits = bytearray(2)
    set_bit(bits, 3)
    assert is_set(bits, 3)
    set_bit(bits, 3, False)
    assert not is_set(bits, 3)
    with pytest.raises(StatusListError):
        StatusListManager(tmp_path / "bad-url", private_key, "Issuer", "https:///missing-host")
    with pytest.raises(StatusListError, match="invalid port"):
        StatusListManager(
            tmp_path / "bad-port", private_key, "Issuer", "https://issuer.example:not-a-port/list"
        )
    with pytest.raises(StatusListError):
        create_status_entry("http://example.com/list", 0)


def test_status_list_rejects_wrong_issuer_and_modified_list(tmp_path, private_key) -> None:
    from skillcred.keys import generate_keypair

    url = "https://issuer.example/status-list"
    manager = StatusListManager(tmp_path / "state", private_key, "Issuer", url)
    entry = manager.allocate()
    credential = create_credential(
        private_key,
        issuer_name="Issuer",
        achievement_name="Skill",
        achievement_description="Test",
        credential_status=entry,
    )
    other_key = generate_keypair()
    other_credential = create_credential(
        other_key,
        issuer_name="Other issuer",
        achievement_name="Skill",
        achievement_description="Test",
        credential_status=entry,
    )
    status_list = manager.create_credential()
    with pytest.raises(StatusListError, match="issuers do not match"):
        check_credential_status(other_credential, status_list)
    changed = dict(status_list)
    changed["credentialSubject"] = dict(status_list["credentialSubject"])
    changed["credentialSubject"]["encodedList"] = "uZm9v"
    with pytest.raises(StatusListError, match="signature is invalid"):
        check_credential_status(credential, changed)


def test_status_list_rejects_out_of_range_index(tmp_path, private_key) -> None:
    manager = StatusListManager(
        tmp_path / "state", private_key, "Issuer", "https://issuer.example/status-list"
    )
    entry = manager.allocate()
    entry["statusListIndex"] = "131072"
    entry["id"] = f"{entry['statusListCredential']}#131072"
    credential = {"issuer": {"id": manager.issuer_id}, "credentialStatus": entry}
    with pytest.raises(StatusListError, match="outside encodedList"):
        check_credential_status(credential, manager.create_credential())


def test_status_list_manager_status_and_capacity(tmp_path, private_key) -> None:
    import json

    manager = StatusListManager(
        tmp_path, private_key, "Issuer", "https://issuer.example/status-list"
    )
    manager.allocate()
    assert manager.status_for_index(0) == "active"
    manager.revoke(0)
    assert manager.status_for_index(0) == "revoked"
    with pytest.raises(StatusListError, match="Unknown statusListIndex"):
        manager.status_for_index(1)
    with pytest.raises(StatusListError, match="must be an integer"):
        manager.revoke(True)
    state = {
        "version": 2,
        "issuer_id": manager.issuer_id,
        "status_list_url": manager.status_list_url,
        "next_index": 131072,
        "revoked_indices": [0],
    }
    manager.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(StatusListError, match="Status list is full"):
        manager.allocate()


def test_state_rejects_revoked_index_above_next_index(tmp_path, private_key) -> None:
    import json

    manager = StatusListManager(
        tmp_path, private_key, "Issuer", "https://issuer.example/status-list"
    )
    state = {
        "version": 2,
        "issuer_id": manager.issuer_id,
        "status_list_url": manager.status_list_url,
        "next_index": 0,
        "revoked_indices": [0],
    }
    manager.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(StatusListError, match="Malformed revoked index"):
        manager.allocate()


def test_status_list_rejects_boolean_revocation_index(private_key) -> None:
    from skillcred.statuslist import create_status_list_credential

    with pytest.raises(StatusListError, match="not booleans"):
        create_status_list_credential(
            private_key,
            issuer_name="Issuer",
            status_list_url="https://issuer.example/status-list",
            revoked_indices={True},
        )
