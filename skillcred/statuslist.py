"""Local issuer-managed W3C Bitstring Status List support.

This implements a focused revocation-only status list: 131072 bits minimum,
left-most-bit-first index encoding, gzip compression and base64url without padding. The
published list is a signed Verifiable Credential. This is not the obsolete
StatusList2021 format; see SPEC.md for conformance boundaries.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import tempfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skillcred.badge import VC_CONTEXT, add_proof, utc_now
from skillcred.keys import identity_from_private_key
from skillcred.verify import verify_signature

MIN_BITS = 131_072
LIST_TYPE = "BitstringStatusListCredential"
ENTRY_TYPE = "BitstringStatusListEntry"
SUBJECT_TYPE = "BitstringStatusList"


class StatusListError(ValueError):
    """Raised when status-list data is malformed or cannot be persisted."""


def _base64url(data: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("u"):
        raise StatusListError("encodedList must use the base64url multibase prefix u")
    if len(value) > 24 * 1024 * 1024:
        raise StatusListError("Encoded status list is unexpectedly large")
    if re.fullmatch(r"u[A-Za-z0-9_-]+", value) is None:
        raise StatusListError("encodedList contains invalid base64url characters")
    try:
        return base64.urlsafe_b64decode(value[1:] + "=" * (-len(value[1:]) % 4))
    except (ValueError, TypeError) as exc:
        raise StatusListError("Invalid base64url encodedList") from exc


def encode_list(bits: bytearray) -> str:
    if len(bits) < MIN_BITS // 8:
        raise StatusListError(f"Status list must contain at least {MIN_BITS} bits")
    return _base64url(gzip.compress(bytes(bits), mtime=0))


def decode_list(encoded_list: str) -> bytearray:
    compressed = _decode_base64url(encoded_list)
    try:
        inflater = zlib.decompressobj(wbits=31)
        decompressor = inflater.decompress(compressed, 16 * 1024 * 1024 + 1)
        if (
            len(decompressor) > 16 * 1024 * 1024
            or inflater.unconsumed_tail
            or inflater.unused_data
        ):
            raise StatusListError("Decoded status list is unexpectedly large or has trailing data")
        decompressor += inflater.flush(16 * 1024 * 1024 + 1 - len(decompressor))
        if not inflater.eof:
            raise StatusListError("encodedList is not a complete gzip stream")
    except (OSError, EOFError, zlib.error) as exc:
        raise StatusListError("encodedList is not a valid gzip stream") from exc
    if len(decompressor) < MIN_BITS // 8:
        raise StatusListError("Decoded status list is shorter than the required minimum")
    if len(decompressor) > 16 * 1024 * 1024:
        raise StatusListError("Decoded status list is unexpectedly large")
    return bytearray(decompressor)


def is_set(bits: bytes | bytearray, index: int) -> bool:
    if index < 0 or index >= len(bits) * 8:
        raise StatusListError("statusListIndex is outside encodedList")
    return bool(bits[index // 8] & (1 << (7 - (index % 8))))


def set_bit(bits: bytearray, index: int, value: bool = True) -> None:
    if index < 0 or index >= len(bits) * 8:
        raise StatusListError("statusListIndex is outside encodedList")
    mask = 1 << (7 - (index % 8))
    if value:
        bits[index // 8] |= mask
    else:
        bits[index // 8] &= ~mask


def _validate_status_list_url(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2000:
        raise StatusListError("status_list_url must be a non-empty URL of at most 2000 characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise StatusListError("status_list_url is malformed or contains an invalid port") from exc
    if port == 0:
        raise StatusListError("status_list_url port must be between 1 and 65535")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise StatusListError("status_list_url must not contain credentials or a fragment")
    if parsed.scheme == "https" and parsed.hostname:
        return value
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return value
    raise StatusListError("status_list_url must use https (localhost is allowed for development)")


def create_status_list_credential(
    private_key: Ed25519PrivateKey,
    *,
    issuer_name: str,
    status_list_url: str,
    revoked_indices: set[int],
) -> dict[str, Any]:
    status_list_url = _validate_status_list_url(status_list_url)
    if any(not isinstance(index, int) or isinstance(index, bool) for index in revoked_indices):
        raise StatusListError("Revoked status indexes must be integers, not booleans")
    bits = bytearray(MIN_BITS // 8)
    for index in revoked_indices:
        set_bit(bits, index)
    identity = identity_from_private_key(private_key)
    unsecured: dict[str, Any] = {
        "@context": [VC_CONTEXT],
        "id": status_list_url,
        "type": ["VerifiableCredential", LIST_TYPE],
        "issuer": {"id": identity.did, "type": ["Profile"], "name": issuer_name},
        "validFrom": utc_now(),
        "credentialSubject": {
            "id": f"{status_list_url}#list",
            "type": SUBJECT_TYPE,
            "statusPurpose": "revocation",
            "encodedList": encode_list(bits),
        },
    }
    return add_proof(unsecured, private_key)


def create_status_entry(status_list_url: str, index: int) -> dict[str, Any]:
    status_list_url = _validate_status_list_url(status_list_url)
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= MIN_BITS:
        raise StatusListError("statusListIndex outside supported MVP capacity")
    return {
        "id": f"{status_list_url}#{index}",
        "type": ENTRY_TYPE,
        "statusPurpose": "revocation",
        "statusListIndex": str(index),
        "statusListCredential": status_list_url,
    }


def check_credential_status(
    credential: dict[str, Any], status_list_credential: dict[str, Any]
) -> str:
    entry = credential.get("credentialStatus")
    if not isinstance(entry, dict) or entry.get("type") != ENTRY_TYPE:
        raise StatusListError("Credential does not contain a supported BitstringStatusListEntry")
    if not verify_signature(status_list_credential):
        raise StatusListError("Status list credential signature is invalid")
    list_types = status_list_credential.get("type", [])
    if not isinstance(list_types, list) or LIST_TYPE not in list_types:
        raise StatusListError("Status credential does not declare BitstringStatusListCredential")
    list_url = status_list_credential.get("id")
    if not isinstance(list_url, str) or list_url != entry.get("statusListCredential"):
        raise StatusListError("Status list URL does not match credential status entry")
    issuer = credential.get("issuer")
    list_issuer = status_list_credential.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
    list_issuer_id = list_issuer.get("id") if isinstance(list_issuer, dict) else list_issuer
    if issuer_id != list_issuer_id:
        raise StatusListError("Credential and status list issuers do not match")
    purpose = entry.get("statusPurpose")
    if purpose != "revocation":
        raise StatusListError("Only revocation status is supported by the MVP")
    if not isinstance(entry.get("statusListIndex"), str):
        raise StatusListError("statusListIndex must be a string")
    try:
        index = int(entry["statusListIndex"])
    except (KeyError, ValueError, TypeError) as exc:
        raise StatusListError("statusListIndex must be a decimal integer") from exc
    if str(index) != entry["statusListIndex"]:
        raise StatusListError("statusListIndex is not canonically encoded")
    if entry.get("id") != f"{entry['statusListCredential']}#{index}":
        raise StatusListError("credentialStatus id does not match list URL and index")
    subject = status_list_credential.get("credentialSubject")
    if not isinstance(subject, dict) or subject.get("statusPurpose") != purpose:
        raise StatusListError("Status-list credential has an unexpected purpose")
    if subject.get("type") != SUBJECT_TYPE:
        raise StatusListError("Status-list credential subject type is invalid")
    if subject.get("id") != f"{list_url}#list":
        raise StatusListError("Status-list credential subject identifier is invalid")
    bits = decode_list(str(subject.get("encodedList", "")))
    return "revoked" if is_set(bits, index) else "active"


class StatusListManager:
    """Single-issuer local status manager; no recipient identifiers are stored."""

    def __init__(
        self,
        data_dir: str | Path,
        private_key: Ed25519PrivateKey,
        issuer_name: str,
        status_list_url: str,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.private_key = private_key
        self.issuer_name = issuer_name
        self.issuer_id = identity_from_private_key(private_key).did
        self.status_list_url = _validate_status_list_url(status_list_url)
        self.state_path = self.data_dir / "status-state.json"
        self.lock_path = self.data_dir / "status-state.lock"
        with self._exclusive_state():
            pass

    @contextmanager
    def _exclusive_state(self) -> Iterator[None]:
        """Serialize status mutations across threads/processes on supported OSes."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as lock_stream:
            with suppress(OSError):
                os.chmod(self.lock_path, 0o600)
            if os.name == "nt":
                import msvcrt

                lock_stream.seek(0, os.SEEK_END)
                if lock_stream.tell() == 0:
                    lock_stream.write(b"\0")
                    lock_stream.flush()
                lock_stream.seek(0)
                msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
            try:
                self._state = self._read_state()
                yield
                self._save()
            finally:
                if os.name == "nt":
                    import msvcrt

                    lock_stream.seek(0)
                    msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)

    def _read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "version": 2,
                "issuer_id": self.issuer_id,
                "status_list_url": self.status_list_url,
                "next_index": 0,
                "revoked_indices": [],
            }
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise StatusListError("Malformed status state root")
            if data.get("version") != 2:
                raise StatusListError("Unsupported status state version")
            if data.get("issuer_id") != self.issuer_id:
                raise StatusListError("Status state is bound to a different issuer key")
            if data.get("status_list_url") != self.status_list_url:
                raise StatusListError("Status state is bound to a different status-list URL")
            revoked = data.get("revoked_indices", [])
            next_index = data.get("next_index", 0)
            if (
                not isinstance(revoked, list)
                or not isinstance(next_index, int)
                or isinstance(next_index, bool)
            ):
                raise StatusListError("Malformed status state")
            if any(
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index >= MIN_BITS
                or index >= next_index
                for index in revoked
            ):
                raise StatusListError("Malformed revoked index")
            if not 0 <= next_index <= MIN_BITS:
                raise StatusListError("Status list capacity exhausted")
            return {
                "version": 2,
                "issuer_id": self.issuer_id,
                "status_list_url": self.status_list_url,
                "next_index": next_index,
                "revoked_indices": sorted(set(revoked)),
            }
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
            raise StatusListError("Could not read status state") from exc

    def _save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".status-state.", dir=self.data_dir)
        path = Path(name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self._state, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(path, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            if path.exists():
                path.unlink()

    def allocate(self) -> dict[str, Any]:
        with self._exclusive_state():
            index = int(self._state["next_index"])
            if index >= MIN_BITS:
                raise StatusListError("Status list is full; rotate to a new list")
            self._state["next_index"] = index + 1
            return create_status_entry(self.status_list_url, index)

    def revoke(self, index: int) -> None:
        if not isinstance(index, int) or isinstance(index, bool):
            raise StatusListError("status index must be an integer")
        with self._exclusive_state():
            if index < 0 or index >= self._state["next_index"]:
                raise StatusListError("Cannot revoke an index that has not been allocated")
            revoked = set(self._state["revoked_indices"])
            revoked.add(index)
            self._state["revoked_indices"] = sorted(revoked)

    def create_credential(self) -> dict[str, Any]:
        with self._exclusive_state():
            revoked = set(self._state["revoked_indices"])
            return create_status_list_credential(
                self.private_key,
                issuer_name=self.issuer_name,
                status_list_url=self.status_list_url,
                revoked_indices=revoked,
            )

    def status_for_index(self, index: int) -> str:
        with self._exclusive_state():
            if index < 0 or index >= self._state["next_index"]:
                raise StatusListError("Unknown statusListIndex")
            return "revoked" if index in set(self._state["revoked_indices"]) else "active"
