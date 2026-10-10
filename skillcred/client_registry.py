"""Encrypted client lifecycle registry and Ed25519-signed short-lived JWTs.

The registry is intended for a single API instance or a shared, single-writer
filesystem. Use an external transactional store before running multiple replicas.
Access tokens are compact JWS JWTs with alg=EdDSA (RFC 8037); each token is
checked against encrypted state so per-token and per-client revocation take effect.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from skillcred.keys import identity_from_private_key

_MAGIC = b"SCC1"
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
ROLES = frozenset({"issuer", "revoker", "verifier", "admin"})
ROLE_SCOPES = {
    "issuer": frozenset({"credential:issue"}),
    "revoker": frozenset({"credential:revoke"}),
    "verifier": frozenset({"credential:verify", "impact:write"}),
    "admin": frozenset({"*"}),
}
ROLE_DEFAULT_SCOPES = {
    "issuer": frozenset({"credential:issue"}),
    "revoker": frozenset({"credential:revoke"}),
    "verifier": frozenset({"credential:verify"}),
    "admin": frozenset({"*"}),
}
_ALLOWED_SCOPES = frozenset().union(*ROLE_SCOPES.values())


class ClientRegistryError(ValueError):
    """Registry operation failed or stored registry is unavailable."""


class TokenRejected(ClientRegistryError):
    """Token is invalid, expired, revoked, or lacks permission."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(value: str) -> bytes:
    if not value or any(
        ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value
    ):
        raise TokenRejected("Malformed JWT base64url segment")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ClientRegistryError("Client registry passphrase must contain at least 12 characters")
    return Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        with suppress(OSError):
            os.chmod(path, 0o600)
    finally:
        if temp.exists():
            temp.unlink()


class ClientRegistry:
    """Encrypted client state plus signed, expiring, revocable JWT issuance."""

    def __init__(
        self,
        path: str | Path,
        passphrase: str,
        signing_key: Ed25519PrivateKey,
        *,
        audience: str = "skillcred-api",
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.passphrase = passphrase
        self.signing_key = signing_key
        self.public_key: Ed25519PublicKey = signing_key.public_key()
        self.issuer_id = identity_from_private_key(signing_key).did
        self.audience = audience
        self._lock = threading.RLock()
        if not self.path.exists():
            self._write({"schema_version": 1, "clients": {}, "tokens": {}})
        else:
            self._read()  # Fail closed during startup if decrypt/structure fails.

    def _read(self) -> dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise ClientRegistryError("Client registry cannot be read") from exc
        min_len = len(_MAGIC) + _SALT_LEN + _NONCE_LEN + 16
        if len(raw) < min_len or not raw.startswith(_MAGIC):
            raise ClientRegistryError("Client registry format is invalid")
        offset = len(_MAGIC)
        salt = raw[offset : offset + _SALT_LEN]
        offset += _SALT_LEN
        nonce = raw[offset : offset + _NONCE_LEN]
        ciphertext = raw[offset + _NONCE_LEN :]
        try:
            plain = AESGCM(_derive(self.passphrase, salt)).decrypt(nonce, ciphertext, _MAGIC)
            value = json.loads(plain)
        except (InvalidTag, ValueError, json.JSONDecodeError) as exc:
            raise ClientRegistryError("Client registry cannot be decrypted") from exc
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or not isinstance(value.get("clients"), dict)
            or not isinstance(value.get("tokens"), dict)
        ):
            raise ClientRegistryError("Client registry structure is invalid")
        return value

    def _write(self, value: dict[str, Any]) -> None:
        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)
        plain = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(_derive(self.passphrase, salt)).encrypt(nonce, plain, _MAGIC)
        _atomic_write(self.path, _MAGIC + salt + nonce + ciphertext)

    def register_client(
        self, name: str, roles: list[str], scopes: list[str] | None = None
    ) -> dict[str, Any]:
        clean_name = name.strip()
        if not clean_name or len(clean_name) > 120:
            raise ClientRegistryError("Client name must contain 1..120 characters")
        role_set = set(roles)
        if not role_set or not role_set <= ROLES:
            raise ClientRegistryError("At least one valid role is required")
        if "admin" in role_set and os.environ.get("SKILLCRED_ALLOW_CLIENT_ADMIN") != "true":
            raise ClientRegistryError(
                "Creating admin clients requires SKILLCRED_ALLOW_CLIENT_ADMIN=true"
            )
        allowed = set().union(*(ROLE_SCOPES[role] for role in role_set))
        default_scopes = set().union(*(ROLE_DEFAULT_SCOPES[role] for role in role_set))
        scope_set = set(scopes) if scopes is not None else default_scopes
        if not scope_set or not scope_set <= allowed or not scope_set <= _ALLOWED_SCOPES:
            raise ClientRegistryError("Scopes must be valid and permitted by the selected roles")
        client_id = uuid.uuid4().hex
        record = {
            "client_id": client_id,
            "name": clean_name,
            "roles": sorted(role_set),
            "scopes": sorted(scope_set),
            "status": "active",
            "token_version": 1,
            "created_at": int(time.time()),
        }
        with self._lock:
            data = self._read()
            data["clients"][client_id] = record
            self._write(data)
        return {
            key: record[key]
            for key in ("client_id", "name", "roles", "scopes", "status", "created_at")
        }

    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            data = self._read()
            return [
                {
                    k: client[k]
                    for k in ("client_id", "name", "roles", "scopes", "status", "created_at")
                }
                for client in sorted(data["clients"].values(), key=lambda item: item["created_at"])
            ]

    def _sign_token(
        self, client: dict[str, Any], ttl_seconds: int, scopes: list[str] | None = None
    ) -> dict[str, Any]:
        if not 60 <= ttl_seconds <= 30 * 24 * 60 * 60:
            raise ClientRegistryError("expires_in must be between 60 seconds and 30 days")
        scope_set = set(client["scopes"]) if scopes is None else set(scopes)
        if not scope_set or not scope_set <= set(client["scopes"]):
            raise ClientRegistryError("Requested token scopes exceed the client's grants")
        now = int(time.time())
        jti = uuid.uuid4().hex
        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": identity_from_private_key(self.signing_key).verification_method,
        }
        payload = {
            "iss": self.issuer_id,
            "sub": client["client_id"],
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": jti,
            "ver": int(client["token_version"]),
            "roles": client["roles"],
            "scope": " ".join(sorted(scope_set)),
        }
        header_part = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
        payload_part = _b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        signature = self.signing_key.sign(signing_input)
        compact = f"{header_part}.{payload_part}.{_b64u(signature)}"
        return {
            "access_token": compact,
            "token_type": "Bearer",
            "expires_in": ttl_seconds,
            "jti": jti,
            "scopes": sorted(scope_set),
        }

    def issue_token(
        self, client_id: str, ttl_seconds: int = 3600, scopes: list[str] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            client = data["clients"].get(client_id)
            if not client or client.get("status") != "active":
                raise ClientRegistryError("Client does not exist or is revoked")
            token = self._sign_token(client, ttl_seconds, scopes)
            data["tokens"][token["jti"]] = {
                "client_id": client_id,
                "token_version": int(client["token_version"]),
                "expires_at": int(time.time()) + ttl_seconds,
                "revoked": False,
            }
            self._write(data)
            return token

    def rotate_token(self, client_id: str, ttl_seconds: int = 3600) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            client = data["clients"].get(client_id)
            if not client or client.get("status") != "active":
                raise ClientRegistryError("Client does not exist or is revoked")
            client["token_version"] = int(client["token_version"]) + 1
            token = self._sign_token(client, ttl_seconds)
            data["tokens"][token["jti"]] = {
                "client_id": client_id,
                "token_version": int(client["token_version"]),
                "expires_at": int(time.time()) + ttl_seconds,
                "revoked": False,
            }
            self._write(data)
            return token

    def revoke_client(self, client_id: str) -> None:
        with self._lock:
            data = self._read()
            client = data["clients"].get(client_id)
            if not client:
                raise ClientRegistryError("Client does not exist")
            client["status"] = "revoked"
            client["token_version"] = int(client["token_version"]) + 1
            self._write(data)

    def revoke_token(self, jti: str) -> None:
        with self._lock:
            data = self._read()
            token = data["tokens"].get(jti)
            if not token:
                raise ClientRegistryError("Token does not exist")
            token["revoked"] = True
            self._write(data)

    def authenticate(self, compact: str, required_role: str, required_scope: str) -> dict[str, Any]:
        if len(compact) > 16_384:
            raise TokenRejected("JWT exceeds maximum length")
        parts = compact.split(".")
        if len(parts) != 3:
            raise TokenRejected("Not a compact JWT")
        try:
            header = json.loads(_unb64u(parts[0]))
            claims = json.loads(_unb64u(parts[1]))
            signature = _unb64u(parts[2])
            if (
                not isinstance(header, dict)
                or set(header) != {"alg", "typ", "kid"}
                or header.get("alg") != "EdDSA"
                or header.get("typ") != "JWT"
            ):
                raise TokenRejected("Unsupported JWT header")
            expected_kid = identity_from_private_key(self.signing_key).verification_method
            if header.get("kid") != expected_kid:
                raise TokenRejected("JWT key identifier does not match issuer key")
            if not isinstance(claims, dict):
                raise TokenRejected("JWT claims must be an object")
            self.public_key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
        except TokenRejected:
            raise
        except Exception as exc:
            raise TokenRejected("JWT signature or serialization is invalid") from exc
        now = int(time.time())
        if claims.get("iss") != self.issuer_id or claims.get("aud") != self.audience:
            raise TokenRejected("JWT issuer or audience does not match")
        if not isinstance(claims.get("exp"), int) or now >= claims["exp"]:
            raise TokenRejected("JWT is expired or has no valid expiry")
        if not isinstance(claims.get("nbf"), int) or now < claims["nbf"]:
            raise TokenRejected("JWT is not active yet")
        if not isinstance(claims.get("iat"), int) or claims["iat"] > now + 5:
            raise TokenRejected("JWT issued-at claim is invalid")
        jti = claims.get("jti")
        client_id = claims.get("sub")
        roles = claims.get("roles")
        scope_set = set(str(claims.get("scope", "")).split())
        if (
            not isinstance(jti, str)
            or not isinstance(client_id, str)
            or not isinstance(roles, list)
        ):
            raise TokenRejected("JWT is missing required claims")
        with self._lock:
            data = self._read()
            client = data["clients"].get(client_id)
            token_record = data["tokens"].get(jti)
            if not client or client.get("status") != "active" or not token_record:
                raise TokenRejected("Client or token has been revoked")
            if token_record.get("revoked") or token_record.get("expires_at", 0) <= now:
                raise TokenRejected("Token has been revoked or expired")
            if claims.get("ver") != client.get("token_version") or token_record.get(
                "token_version"
            ) != client.get("token_version"):
                raise TokenRejected("Token has been superseded by rotation")
            if "admin" not in roles and required_role not in roles:
                raise TokenRejected("Token does not grant the required role")
            if "*" not in scope_set and required_scope not in scope_set:
                raise TokenRejected("Token does not grant the required scope")
        return claims

    def verified_roles_for_rate_limit(self, compact: str) -> set[str]:
        """Return roles from a fully verified current token for quota selection.

        This is not an authorization decision; protected handlers still call
        authenticate with an exact role and scope. Invalid tokens return an empty set.
        """
        try:
            parts = compact.split(".")
            if len(parts) != 3:
                return set()
            untrusted = json.loads(_unb64u(parts[1]))
            candidate_roles = untrusted.get("roles", []) if isinstance(untrusted, dict) else []
            scopes = (
                set(str(untrusted.get("scope", "")).split())
                if isinstance(untrusted, dict)
                else set()
            )
            result: set[str] = set()
            for role in candidate_roles:
                permitted = ROLE_SCOPES.get(role, frozenset())
                matched = (
                    "*"
                    if role == "admin" and "*" in scopes
                    else next(iter(permitted.intersection(scopes)), None)
                )
                if matched:
                    self.authenticate(compact, role, matched)
                    result.add(role)
            return result
        except (TokenRejected, ClientRegistryError, ValueError, TypeError):
            return set()
