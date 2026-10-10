from __future__ import annotations

import copy

from skillcred.badge import create_credential
from skillcred.verify import verify_credential, verify_signature


def make_credential(private_key):
    return create_credential(
        private_key,
        issuer_name="Pilot Org",
        achievement_name="First Aid Basics",
        achievement_description="Demonstrated the listed practical skills.",
        subject_id="urn:person:learner-123",
    )


def test_issued_credential_verifies(private_key) -> None:
    credential = make_credential(private_key)
    assert verify_signature(credential)
    result = verify_credential(credential)
    assert result["signature_valid"] is True
    assert result["valid"] is True
    assert result["issuer"].startswith("did:key:")


def test_tampering_is_detected(private_key) -> None:
    credential = make_credential(private_key)
    credential["credentialSubject"]["achievement"]["name"] = "Forged achievement"
    assert not verify_signature(credential)
    assert not verify_credential(credential)["valid"]


def test_proof_tampering_is_detected(private_key) -> None:
    credential = make_credential(private_key)
    changed = copy.deepcopy(credential)
    changed["proof"]["proofValue"] = changed["proof"]["proofValue"][:-1] + "1"
    assert not verify_signature(changed)


def test_no_subject_identifier_is_issued_by_default(private_key) -> None:
    credential = create_credential(
        private_key,
        issuer_name="Pilot Org",
        achievement_name="Accessible Skill",
        achievement_description="No learner ID required.",
    )
    subject_id = credential["credentialSubject"]["id"]
    assert subject_id.startswith("urn:uuid:")
    assert (
        "No learner ID required." in credential["credentialSubject"]["achievement"]["description"]
    )

    second = create_credential(
        private_key,
        issuer_name="Pilot Org",
        achievement_name="Accessible Skill",
        achievement_description="No learner ID required.",
    )
    assert second["credentialSubject"]["id"] != subject_id


def test_rejects_empty_issuer_and_achievement(private_key) -> None:
    import pytest

    with pytest.raises(ValueError):
        create_credential(
            private_key, issuer_name=" ", achievement_name="A", achievement_description="B"
        )
    with pytest.raises(ValueError):
        create_credential(
            private_key, issuer_name="Issuer", achievement_name=" ", achievement_description="B"
        )


def test_rejects_overlong_text(private_key) -> None:
    import pytest

    with pytest.raises(ValueError):
        create_credential(
            private_key,
            issuer_name="Issuer",
            achievement_name="x" * 201,
            achievement_description="B",
        )
    with pytest.raises(ValueError):
        create_credential(
            private_key,
            issuer_name="Issuer",
            achievement_name="A",
            achievement_description="x" * 4001,
        )


def test_rejects_wrong_issuer_even_if_signed_by_key(private_key) -> None:
    import pytest
    from skillcred.badge import add_proof
    from skillcred.verify import VerificationError

    credential = make_credential(private_key)
    unsecured = copy.deepcopy(credential)
    unsecured.pop("proof")
    unsecured["issuer"]["id"] = "did:key:z6MkpNotTheSigningKey"
    maliciously_signed = add_proof(unsecured, private_key)
    with pytest.raises(VerificationError):
        verify_signature(maliciously_signed)


def test_malformed_and_unsupported_proofs_are_rejected(private_key) -> None:
    import pytest
    from skillcred.verify import VerificationError

    credential = make_credential(private_key)
    missing = copy.deepcopy(credential)
    missing.pop("proof")
    with pytest.raises(VerificationError):
        verify_signature(missing)
    multiple = copy.deepcopy(credential)
    multiple["proof"] = [credential["proof"], credential["proof"]]
    with pytest.raises(VerificationError):
        verify_signature(multiple)
    unsupported = copy.deepcopy(credential)
    unsupported["proof"]["cryptosuite"] = "unknown-suite"
    with pytest.raises(VerificationError):
        verify_signature(unsupported)
    wrong_context = copy.deepcopy(credential)
    wrong_context["proof"]["@context"] = ["https://example.invalid/context"]
    with pytest.raises(VerificationError):
        verify_signature(wrong_context)


def test_unsigned_status_cannot_be_reported_valid(private_key) -> None:
    credential = make_credential(private_key)
    credential["credentialStatus"] = {
        "id": "https://issuer.example/status-list#0",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "0",
        "statusListCredential": "https://issuer.example/status-list",
    }
    # Adding status after signing must fail signature verification.
    result = verify_credential(credential)
    assert result["valid"] is False


def test_non_object_and_wrong_key_method_are_rejected() -> None:
    import pytest
    from skillcred.verify import VerificationError, extract_public_key, verify_signature

    with pytest.raises(VerificationError, match="JSON object"):
        verify_signature(["not", "an", "object"])
    with pytest.raises(VerificationError, match="DID URL"):
        extract_public_key("not-a-did-url")
    with pytest.raises(VerificationError, match="Only self-certifying"):
        extract_public_key("https://issuer.example/key#z123")
