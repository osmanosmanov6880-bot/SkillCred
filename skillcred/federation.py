"""Explicit, privacy-preserving issuer discovery and local trust pins.

Discovery only publishes metadata; it does not imply trust. This module never fetches a
remote URL. Operators must inspect metadata, compare the DID out of band, and explicitly
pin the expected DID. A pin is a local operator decision, not a global certification.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from skillcred.keys import KeyFormatError, decode_multibase_ed25519, did_key


class FederationError(ValueError):
    """Issuer metadata or local trust-pin operation was invalid."""


def _safe_service_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise FederationError(f"{field} must be a URL string")
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise FederationError(f"{field} must be a URL without embedded credentials")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise FederationError(f"{field} must use HTTPS (HTTP is allowed only for localhost)")
    return value


def _validate_did_key(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("did:key:z") or "#" in value:
        return False
    try:
        public_key = decode_multibase_ed25519(value.removeprefix("did:key:"))
        return did_key(public_key) == value
    except (KeyFormatError, ValueError):
        return False


def create_issuer_metadata(
    *, issuer_id: str, name: str, status_list_url: str, version: str = "0.3.0"
) -> dict[str, Any]:
    if not _validate_did_key(issuer_id):
        raise FederationError("issuer_id must be a valid did:key Ed25519 identifier")
    clean_name = name.strip()
    if not clean_name or len(clean_name) > 200:
        raise FederationError("issuer name must contain 1..200 characters")
    _safe_service_url(status_list_url, "status_list_url")
    return {
        "id": issuer_id,
        "type": "SkillCredIssuerMetadata",
        "name": clean_name,
        "skillCredVersion": version,
        "credentialProfiles": ["OpenBadgeCredential", "VerifiableCredential"],
        "proofSuites": ["eddsa-jcs-2022"],
        "statusList": {"type": "BitstringStatusList", "url": status_list_url},
        "discovery": {"trustImplied": False, "remoteFetchPerformed": False},
    }


def validate_issuer_metadata(metadata: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(metadata, dict):
        return ["metadata must be an object"]
    issuer_id = metadata.get("id")
    if not _validate_did_key(issuer_id):
        errors.append("id must be a valid did:key Ed25519 identifier")
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        errors.append("name must contain 1..200 characters")
    if metadata.get("type") != "SkillCredIssuerMetadata":
        errors.append("type must equal SkillCredIssuerMetadata")
    profiles = metadata.get("credentialProfiles")
    if (
        not isinstance(profiles, list)
        or not profiles
        or any(not isinstance(item, str) for item in profiles)
    ):
        errors.append("credentialProfiles must be a non-empty string array")
    suites = metadata.get("proofSuites")
    if not isinstance(suites, list) or "eddsa-jcs-2022" not in suites:
        errors.append("proofSuites must declare eddsa-jcs-2022")
    status = metadata.get("statusList")
    if not isinstance(status, dict) or status.get("type") != "BitstringStatusList":
        errors.append("statusList must describe a BitstringStatusList")
    else:
        try:
            _safe_service_url(status.get("url"), "statusList.url")
        except FederationError as exc:
            errors.append(str(exc))
    discovery = metadata.get("discovery")
    if not isinstance(discovery, dict) or discovery.get("trustImplied") is not False:
        errors.append("discovery.trustImplied must be false")
    return errors


class IssuerTrustStore:
    """Owner-readable local trust pins; no remote requests are performed."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        if not self.path.exists():
            self._write({"schema_version": 1, "issuers": {}})
        elif os.name != "nt":
            os.chmod(self.path, 0o600)

    def _read(self) -> dict[str, Any]:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FederationError("Trust store is unreadable or invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != 1
            or not isinstance(document.get("issuers"), dict)
        ):
            raise FederationError("Trust store structure is invalid")
        return document

    def _write(self, document: dict[str, Any]) -> None:
        data = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        finally:
            if temporary.exists():
                temporary.unlink()

    def pin(
        self, metadata: Any, expected_issuer_id: str, *, operator_note: str = ""
    ) -> dict[str, Any]:
        errors = validate_issuer_metadata(metadata)
        if errors:
            raise FederationError("Invalid issuer metadata: " + "; ".join(errors))
        if metadata["id"] != expected_issuer_id:
            raise FederationError(
                "Issuer DID does not match the independently supplied expected DID"
            )
        if len(operator_note) > 500:
            raise FederationError("operator_note must be at most 500 characters")
        record = {
            "id": metadata["id"],
            "name": metadata["name"],
            "status_list_url": metadata["statusList"]["url"],
            "proof_suites": metadata["proofSuites"],
            "credential_profiles": metadata["credentialProfiles"],
            "operator_note": operator_note.strip(),
        }
        with self._lock:
            document = self._read()
            document["issuers"][metadata["id"]] = record
            self._write(document)
        return dict(record)

    def is_trusted(self, issuer_id: str) -> bool:
        with self._lock:
            document = self._read()
            return issuer_id in document["issuers"]

    def list_pins(self) -> list[dict[str, Any]]:
        with self._lock:
            document = self._read()
            return [dict(value) for _, value in sorted(document["issuers"].items())]

    def unpin(self, issuer_id: str) -> None:
        with self._lock:
            document = self._read()
            if issuer_id not in document["issuers"]:
                raise FederationError("Issuer is not pinned")
            del document["issuers"][issuer_id]
            self._write(document)
