"""Offline cryptographic verification for SkillCred's JCS credential profile."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from skillcred.jcs import CanonicalizationError, canonicalize
from skillcred.keys import KeyFormatError, b58decode, decode_multibase_ed25519, did_key


class VerificationError(ValueError):
    """Raised when a credential is malformed or uses an unsupported proof profile."""


def extract_public_key(verification_method: str) -> Ed25519PublicKey:
    if not isinstance(verification_method, str) or "#" not in verification_method:
        raise VerificationError("verificationMethod must be a DID URL with a key fragment")
    did, fragment = verification_method.split("#", 1)
    if not did.startswith("did:key:"):
        raise VerificationError("Only self-certifying did:key issuers are supported in MVP")
    public_key = decode_multibase_ed25519(fragment)
    if did_key(public_key) != did:
        raise VerificationError("verificationMethod key does not match issuer DID")
    return public_key


def _proof_from_document(credential: dict[str, Any]) -> dict[str, Any]:
    proof = credential.get("proof")
    if isinstance(proof, list):
        if len(proof) != 1:
            raise VerificationError("MVP verifier accepts exactly one proof")
        proof = proof[0]
    if not isinstance(proof, dict):
        raise VerificationError("Credential has no proof object")
    return proof


def verify_signature(credential: dict[str, Any]) -> bool:
    """Verify proof cryptographically without network access or key lookup."""
    if not isinstance(credential, dict):
        raise VerificationError("Credential must be a JSON object")
    proof = _proof_from_document(credential)
    if proof.get("type") != "DataIntegrityProof":
        raise VerificationError("Unsupported proof type; expected DataIntegrityProof")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise VerificationError("Unsupported cryptosuite; expected eddsa-jcs-2022")
    if proof.get("proofPurpose") != "assertionMethod":
        raise VerificationError("Unsupported proofPurpose")
    context = credential.get("@context")
    if not isinstance(context, list) or proof.get("@context") != context:
        raise VerificationError("Proof @context must exactly match credential @context")
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise VerificationError("proofValue must be base58-btc multibase")
    verification_method = proof.get("verificationMethod")
    public_key = extract_public_key(verification_method)
    issuer = credential.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
    expected_issuer = verification_method.split("#", 1)[0]
    if issuer_id != expected_issuer:
        raise VerificationError("Credential issuer does not match proof verification method")
    proof_options = copy.deepcopy(proof)
    del proof_options["proofValue"]
    unsecured = copy.deepcopy(credential)
    del unsecured["proof"]
    try:
        proof_config_hash = hashlib.sha256(canonicalize(proof_options)).digest()
        document_hash = hashlib.sha256(canonicalize(unsecured)).digest()
        signature = b58decode(proof_value[1:])
        if len(signature) != 64:
            return False
        public_key.verify(signature, proof_config_hash + document_hash)
    except (CanonicalizationError, KeyFormatError, InvalidSignature, ValueError) as exc:
        if isinstance(exc, VerificationError):
            raise
        return False
    return True


def verify_credential(
    credential: dict[str, Any], *, status_list_credential: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return verification details; status is only known when list data is supplied."""
    errors: list[str] = []
    try:
        valid_signature = verify_signature(credential)
    except VerificationError as exc:
        return {"valid": False, "signature_valid": False, "status": "unknown", "errors": [str(exc)]}
    if not valid_signature:
        errors.append("Signature verification failed or credential has been modified")
    types = credential.get("type", [])
    if not isinstance(types, list) or "OpenBadgeCredential" not in types:
        errors.append("Credential does not declare OpenBadgeCredential type")
    contexts = credential.get("@context", [])
    ob_context = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
    if not isinstance(contexts, list) or ob_context not in contexts:
        errors.append("Open Badges 3.0 context is missing")
    status = "not-checked"
    if credential.get("credentialStatus") is not None:
        if status_list_credential is None:
            status = "unknown"
            errors.append(
                "Credential has status information but no status-list snapshot was supplied"
            )
        else:
            try:
                from skillcred.statuslist import check_credential_status

                status = check_credential_status(credential, status_list_credential)
                if status == "revoked":
                    errors.append("Credential is revoked")
            except (ValueError, VerificationError) as exc:
                status = "unknown"
                errors.append(f"Status check failed: {exc}")
    return {
        "valid": valid_signature and not errors,
        "signature_valid": valid_signature,
        "status": status,
        "issuer": (
            (credential.get("issuer") or {}).get("id")
            if isinstance(credential.get("issuer"), dict)
            else credential.get("issuer")
        ),
        "credential_id": credential.get("id"),
        "errors": errors,
    }
