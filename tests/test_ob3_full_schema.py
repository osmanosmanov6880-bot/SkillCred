from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillcred.badge import create_credential
from skillcred.conformance import validate_vc_dm2_credential
from skillcred.statuslist import create_status_entry

ROOT = Path(__file__).parents[1]
PILOT_SCHEMA = ROOT / "schemas" / "openbadge-pilot.schema.json"
OFFICIAL_SCHEMA = ROOT / "schemas" / "official_ob3_achievementcredential_schema.json"


def test_openbadge_credential_matches_local_profile_schema(private_key):
    jsonschema = pytest.importorskip("jsonschema")
    credential = create_credential(
        private_key,
        issuer_name="SkillCred Test Issuer",
        achievement_name="Practical Python",
        achievement_description="Passed practical assessment",
        credential_status=create_status_entry("https://issuer.example/status-list", 42),
    )
    schema = json.loads(PILOT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(credential, schema, format_checker=jsonschema.FormatChecker())
    assert validate_vc_dm2_credential(credential) == []


def test_official_schema_is_used_when_vendored(private_key):
    if not OFFICIAL_SCHEMA.exists():
        pytest.skip("Official 1EdTech schema not vendored; network access is unavailable in this environment")
    jsonschema = pytest.importorskip("jsonschema")
    credential = create_credential(
        private_key, issuer_name="Issuer", achievement_name="Skill", achievement_description=""
    )
    schema = json.loads(OFFICIAL_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(credential, schema, format_checker=jsonschema.FormatChecker())


def test_bad_context_and_missing_subject_claim_are_rejected(private_key):
    credential = create_credential(
        private_key, issuer_name="Issuer", achievement_name="Skill", achievement_description=""
    )
    credential["@context"] = ["https://bad.example/context"]
    credential["credentialSubject"] = {}
    errors = validate_vc_dm2_credential(credential)
    assert any("@context" in error for error in errors)
    assert any("credentialSubject" in error for error in errors)
