"""Create a focused Open Badges 3.0-style credential with W3C Data Integrity proof.

The emitted proof uses the W3C `eddsa-jcs-2022` cryptosuite. Full Open Badges
certification requires the official 1EdTech JSON Schema and conformance tests;
this project deliberately labels its current credential shape as a pilot profile.
"""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skillcred.jcs import canonicalize
from skillcred.keys import b58encode, identity_from_private_key

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
OB_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
CREDENTIAL_TYPE = "OpenBadgeCredential"
CRYPTOSUITE = "eddsa-jcs-2022"


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_proof_options(private_key: Ed25519PrivateKey, context: list[str]) -> dict[str, Any]:
    identity = identity_from_private_key(private_key)
    return {
        "@context": copy.deepcopy(context),
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": utc_now(),
        "verificationMethod": identity.verification_method,
        "proofPurpose": "assertionMethod",
    }


def add_proof(document: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Attach a W3C `eddsa-jcs-2022` proof to a JSON-LD credential.

    Algorithm follows W3C Data Integrity EdDSA Cryptosuites: canonicalize the
    unsecured document and proof configuration with RFC 8785, SHA-256 each,
    concatenate proofConfigHash || documentHash, then sign with Ed25519.
    """
    if "proof" in document:
        raise ValueError("Cannot sign a document that already contains proof")
    unsecured = copy.deepcopy(document)
    proof_options = build_proof_options(private_key, list(unsecured.get("@context", [])))
    proof_config_bytes = canonicalize(proof_options)
    document_bytes = canonicalize(unsecured)
    proof_config_hash = hashlib.sha256(proof_config_bytes).digest()
    document_hash = hashlib.sha256(document_bytes).digest()
    hash_data = proof_config_hash + document_hash
    signature = private_key.sign(hash_data)
    proof = {**proof_options, "proofValue": "z" + b58encode(signature)}
    secured = copy.deepcopy(unsecured)
    secured["proof"] = proof
    return secured


def create_credential(
    private_key: Ed25519PrivateKey,
    *,
    issuer_name: str,
    achievement_name: str,
    achievement_description: str,
    subject_id: str | None = None,
    credential_id: str | None = None,
    credential_status: dict[str, Any] | None = None,
    evidence_url: str | None = None,
) -> dict[str, Any]:
    """Issue a minimal skill credential with a per-credential pseudonymous subject ID.

    The caller does not need to know or provide a learner identifier. Open Badges
    3.0's AchievementSubject requires an `id` or `identifier`, so a fresh random
    URN is generated for each credential when `subject_id` is omitted. This
    identifier is not derived from personal data and is not stored centrally.
    """
    if not issuer_name.strip():
        raise ValueError("issuer_name must not be empty")
    if not achievement_name.strip():
        raise ValueError("achievement_name must not be empty")
    if len(achievement_name) > 200 or len(achievement_description) > 4000:
        raise ValueError("Achievement text exceeds profile limits")
    identity = identity_from_private_key(private_key)
    achievement: dict[str, Any] = {
        "id": f"urn:uuid:{uuid4()}",
        "type": ["Achievement"],
        "name": achievement_name.strip(),
        "description": achievement_description.strip(),
    }
    credential_subject: dict[str, Any] = {
        "id": subject_id or f"urn:uuid:{uuid4()}",
        "type": ["AchievementSubject"],
        "achievement": achievement,
    }
    if evidence_url:
        credential_subject["evidence"] = [{"id": evidence_url}]
    credential: dict[str, Any] = {
        "@context": [VC_CONTEXT, OB_CONTEXT],
        "id": credential_id or f"urn:uuid:{uuid4()}",
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "name": achievement_name.strip(),
        "issuer": {"id": identity.did, "type": ["Profile"], "name": issuer_name.strip()},
        "validFrom": utc_now(),
        "credentialSubject": credential_subject,
    }
    if credential_status is not None:
        credential["credentialStatus"] = copy.deepcopy(credential_status)
    return add_proof(credential, private_key)
