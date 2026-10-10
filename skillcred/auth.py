"""Role-based bearer token authorization for the small issuer API.

Preferred routine access uses short-lived, scoped JWTs from the encrypted client registry.
SKILLCRED_API_TOKENS supports a distinct role-token map for migration/emergency use;
SKILLCRED_API_TOKEN or protected SKILLCRED_API_TOKEN_FILE is bootstrap admin only.
"""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import HTTPException

ROLES = frozenset({"issuer", "revoker", "verifier", "admin"})


@dataclass(frozen=True)
class TokenConfig:
    token_roles: tuple[tuple[str, str], ...]
    configured: bool
    source: str


def load_token_config() -> TokenConfig:
    raw = os.environ.get("SKILLCRED_API_TOKENS")
    secret_file = os.environ.get("SKILLCRED_API_TOKENS_FILE")
    if not raw and secret_file:
        try:
            with open(secret_file, encoding="utf-8") as stream:
                raw = stream.read().strip()
        except OSError as exc:
            raise RuntimeError("Could not read SKILLCRED_API_TOKENS_FILE") from exc
    if raw:
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("SKILLCRED_API_TOKENS must be a JSON object") from exc
        if not isinstance(decoded, dict) or not decoded:
            raise RuntimeError("SKILLCRED_API_TOKENS must be a non-empty JSON object")
        entries: list[tuple[str, str]] = []
        for role, token in decoded.items():
            if role not in ROLES:
                raise RuntimeError(f"Unknown SkillCred API role: {role}")
            if not isinstance(token, str) or len(token) < 32 or not token.isascii():
                raise RuntimeError(f"Token for role {role} must be >=32 ASCII characters")
            entries.append((token, role))
        if len({token for token, _ in entries}) != len(entries):
            raise RuntimeError("Each role must use a distinct token")
        return TokenConfig(tuple(entries), True, "role-map")

    legacy = os.environ.get("SKILLCRED_API_TOKEN")
    legacy_file = os.environ.get("SKILLCRED_API_TOKEN_FILE")
    if not legacy and legacy_file:
        try:
            secret_path = os.path.abspath(os.path.expanduser(legacy_file))
            file_stat = os.stat(secret_path)
            if not os.path.isfile(secret_path):
                raise RuntimeError("SKILLCRED_API_TOKEN_FILE must point to a regular file")
            if os.name != "nt" and file_stat.st_mode & 0o077:
                raise RuntimeError(
                    "Bootstrap token file must not be readable by group or other users"
                )
            with open(secret_path, encoding="utf-8") as stream:
                legacy = stream.read().strip()
        except OSError as exc:
            raise RuntimeError("Could not read SKILLCRED_API_TOKEN_FILE") from exc
    if legacy:
        if len(legacy) < 32 or not legacy.isascii():
            raise RuntimeError("Bootstrap admin token must be >=32 ASCII characters")
        return TokenConfig(
            ((legacy, "admin"),),
            True,
            "legacy-admin-file"
            if legacy_file and not os.environ.get("SKILLCRED_API_TOKEN")
            else "legacy-admin",
        )
    return TokenConfig((), False, "unconfigured")


def extract_bearer(authorization: str | None) -> str | None:
    scheme, separator, supplied = (authorization or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied or " " in supplied:
        return None
    if not supplied.isascii():
        return None
    return supplied


def authorized_roles(authorization: str | None, config: TokenConfig) -> set[str]:
    token = extract_bearer(authorization)
    if token is None:
        return set()
    roles: set[str] = set()
    for expected, role in config.token_roles:
        if hmac.compare_digest(token, expected):
            roles.add(role)
    return roles


def require_role(
    authorization: str | None,
    required: str | Iterable[str],
    *,
    config: TokenConfig | None = None,
) -> str:
    """Require any one of the specified roles, with admin as a super-role."""
    selected = config or load_token_config()
    if not selected.configured:
        raise HTTPException(
            status_code=503,
            detail="Protected operation disabled: configure SKILLCRED_API_TOKENS with strong secrets",
        )
    roles = authorized_roles(authorization, selected)
    if not roles:
        token = extract_bearer(authorization)
        if token is None:
            raise HTTPException(
                status_code=401,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(status_code=403, detail="Invalid bearer token")
    requested = {required} if isinstance(required, str) else set(required)
    if "admin" in roles or roles.intersection(requested):
        return "admin" if "admin" in roles else sorted(roles.intersection(requested))[0]
    raise HTTPException(status_code=403, detail="Insufficient role")
