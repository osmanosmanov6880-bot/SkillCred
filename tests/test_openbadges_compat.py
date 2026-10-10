from __future__ import annotations

import json
from pathlib import Path

import pytest
from skillcred.badge import OB_CONTEXT, VC_CONTEXT, create_credential

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "openbadge-pilot.schema.json"


def test_issued_credential_matches_documented_pilot_schema(private_key):
    jsonschema = pytest.importorskip("jsonschema")
    credential = create_credential(
        private_key,
        issuer_name="Test issuer",
        achievement_name="Practical Python",
        achievement_description="Passed a practical assessment",
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(credential, schema)
    assert credential["@context"] == [VC_CONTEXT, OB_CONTEXT]
    assert credential["credentialSubject"]["id"].startswith("urn:uuid:")


def test_pilot_schema_rejects_wrong_cryptosuite(private_key):
    jsonschema = pytest.importorskip("jsonschema")
    credential = create_credential(
        private_key, issuer_name="Issuer", achievement_name="Skill", achievement_description=""
    )
    credential["proof"]["cryptosuite"] = "Ed25519Signature2020"
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(credential, schema)


def test_pyld_presence_is_reported_not_assumed():
    pyld = pytest.importorskip("pyld")
    assert pyld is not None


def test_pilot_schema_requires_subject_id_or_identifier(private_key):
    jsonschema = pytest.importorskip("jsonschema")
    credential = create_credential(
        private_key,
        issuer_name="Test issuer",
        achievement_name="Practical Python",
        achievement_description="Passed practical assessment",
    )
    credential["credentialSubject"].pop("id")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(credential, schema)
