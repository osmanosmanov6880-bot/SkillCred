from __future__ import annotations

import copy

from skillcred.badge import create_credential
from skillcred.conformance import validate_vc_dm2_credential


def test_credential_meets_local_vc_dm2_structural_requirements(private_key):
    credential = create_credential(
        private_key,
        issuer_name="Issuer",
        achievement_name="Safety skill",
        achievement_description="",
    )
    assert validate_vc_dm2_credential(credential) == []


def test_structural_validator_catches_missing_issuer_id(private_key):
    credential = create_credential(
        private_key,
        issuer_name="Issuer",
        achievement_name="Safety skill",
        achievement_description="",
    )
    malformed = copy.deepcopy(credential)
    malformed["issuer"] = {"name": "Issuer"}
    assert any("issuer" in error for error in validate_vc_dm2_credential(malformed))


def test_explicit_learner_identifier_is_optional_but_subject_urn_is_present(private_key):
    credential = create_credential(
        private_key,
        issuer_name="Issuer",
        achievement_name="Safety skill",
        achievement_description="",
    )
    assert credential["credentialSubject"]["id"].startswith("urn:uuid:")
    assert validate_vc_dm2_credential(credential) == []
