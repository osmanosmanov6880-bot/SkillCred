"""Deterministic local structural checks for VC Data Model 2.0 / OB 3.0 profile.

This is not a replacement for JSON-LD processing or the official 1EdTech suite.
It is intentionally network-free and checks structural requirements used by SkillCred.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from skillcred.badge import OB_CONTEXT, VC_CONTEXT


def validate_vc_dm2_credential(
    credential: dict[str, Any], *, open_badges: bool = True
) -> list[str]:
    errors: list[str] = []
    if not isinstance(credential, dict):
        return ["credential must be a JSON object"]
    contexts = credential.get("@context")
    if not isinstance(contexts, list) or not contexts or contexts[0] != VC_CONTEXT:
        errors.append("@context must be an array beginning with the VC Data Model v2 context")
    if open_badges and (
        not isinstance(contexts, list) or len(contexts) < 2 or contexts[1] != OB_CONTEXT
    ):
        errors.append("Open Badges credentials must include the OB 3.0 context after VC v2")
    types = credential.get("type")
    if not isinstance(types, list) or "VerifiableCredential" not in types:
        errors.append("type must include VerifiableCredential")
    if open_badges and (not isinstance(types, list) or "OpenBadgeCredential" not in types):
        errors.append("type must include OpenBadgeCredential")
    if not isinstance(credential.get("id"), str) or not credential["id"].strip():
        errors.append("id must be a non-empty identifier")
    issuer = credential.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
    if not isinstance(issuer_id, str) or not issuer_id:
        errors.append("issuer must be a string or an object with a non-empty id")
    subject = credential.get("credentialSubject")
    subjects = subject if isinstance(subject, list) else [subject]
    if not subjects or any(not isinstance(item, dict) or not item for item in subjects):
        errors.append("credentialSubject must be a non-empty object or array of objects")
    elif open_badges and any(not isinstance(item.get("achievement"), dict) for item in subjects):
        errors.append("Open Badges credentialSubject must contain an achievement object")
    valid_from = credential.get("validFrom")
    if not isinstance(valid_from, str):
        errors.append("validFrom is required for this Open Badges profile")
    else:
        try:
            datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except ValueError:
            errors.append("validFrom must be an ISO 8601 date-time")
    proof = credential.get("proof")
    proofs = proof if isinstance(proof, list) else [proof]
    if not proofs or any(not isinstance(item, dict) for item in proofs):
        errors.append("proof must be an object or non-empty array of proof objects")
    elif not any(
        item.get("type") == "DataIntegrityProof"
        and item.get("cryptosuite") == "eddsa-jcs-2022"
        and isinstance(item.get("verificationMethod"), str)
        and item.get("proofPurpose") == "assertionMethod"
        and isinstance(item.get("proofValue"), str)
        for item in proofs
    ):
        errors.append("proof must contain a supported eddsa-jcs-2022 DataIntegrityProof")
    status = credential.get("credentialStatus")
    if status is not None:
        entries = status if isinstance(status, list) else [status]
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") != "BitstringStatusListEntry":
                errors.append("credentialStatus must use BitstringStatusListEntry in this profile")
                break
            if not isinstance(entry.get("statusListCredential"), str) or not isinstance(
                entry.get("statusListIndex"), str
            ):
                errors.append(
                    "credentialStatus requires statusListCredential and string statusListIndex"
                )
                break
    return errors
