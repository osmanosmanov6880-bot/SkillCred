"""Local-first issuer API with role tokens, rate limiting and encrypted signing keys."""
from __future__ import annotations

import os
import json
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from skillcred.auth import TokenConfig, load_token_config, require_role, extract_bearer
from skillcred.client_registry import ClientRegistry, ClientRegistryError, TokenRejected
from skillcred.badge import create_credential
from skillcred.i18n import language_from_accept_header, translate
from skillcred.keys import (
    generate_keypair,
    identity_from_private_key,
    private_key_from_base64,
)
from skillcred.metrics import MetricsBundle
from skillcred.impact import ImpactRecordRequest, ImpactStore
from skillcred.federation import FederationError, IssuerTrustStore, create_issuer_metadata
from skillcred.rate_limit import RateLimitMiddleware
from skillcred.request_size import RequestSizeLimitMiddleware
from skillcred.statuslist import StatusListError, StatusListManager
from skillcred.storage import (
    WalletError,
    load_wallet,
    save_wallet,
    wallet_from_key,
)
from skillcred.verify import verify_credential


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    achievement_name: str = Field(min_length=1, max_length=200)
    achievement_description: str = Field(default="", max_length=4000)
    subject_id: str | None = Field(default=None, max_length=500)
    evidence_url: str | None = Field(default=None, max_length=2000)

    @field_validator("achievement_name")
    @classmethod
    def validate_achievement_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("achievement_name must contain non-whitespace characters")
        return value.strip()

    @field_validator("subject_id")
    @classmethod
    def normalize_subject_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("subject_id must not be blank when provided")
        return normalized

    @field_validator("evidence_url")
    @classmethod
    def validate_evidence_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        url = urlsplit(value)
        if (
            not url.hostname
            or url.username is not None
            or url.password is not None
            or url.scheme not in {"https", "http"}
            or (url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"})
        ):
            raise ValueError("evidence_url must be HTTPS (HTTP is allowed only for localhost)")
        try:
            port = url.port
        except ValueError as exc:
            raise ValueError("evidence_url contains an invalid port") from exc
        if port == 0:
            raise ValueError("evidence_url port must be between 1 and 65535")
        return value


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential: dict[str, Any]
    status_list_credential: dict[str, Any] | None = None


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status_list_index: int = Field(ge=0, le=131071)


class ClientCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    roles: list[str] = Field(min_length=1, max_length=4)
    scopes: list[str] | None = Field(default=None, max_length=8)


class ClientTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_in: int = Field(default=3600, ge=60, le=2_592_000)
    scopes: list[str] | None = Field(default=None, max_length=8)


class IssuerPinRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metadata: dict[str, Any]
    expected_issuer_id: str = Field(min_length=20, max_length=512)
    operator_note: str = Field(default="", max_length=500)


def _read_passphrase() -> str | None:
    value = os.environ.get("SKILLCRED_KEY_PASSPHRASE")
    if value:
        if len(value) < 12:
            raise RuntimeError("API wallet passphrase must contain at least 12 characters")
        return value
    secret_file = os.environ.get("SKILLCRED_KEY_PASSPHRASE_FILE")
    if not secret_file:
        return None
    path = Path(secret_file).expanduser()
    try:
        stat = path.stat()
        if not path.is_file():
            raise RuntimeError("SKILLCRED_KEY_PASSPHRASE_FILE must point to a regular file")
        if os.name != "nt" and stat.st_mode & 0o077:
            raise RuntimeError("Passphrase secret file must not be readable by group or others")
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise RuntimeError("Could not read SKILLCRED_KEY_PASSPHRASE_FILE") from exc
    if not value:
        return None
    if len(value) < 12:
        raise RuntimeError("API wallet passphrase must contain at least 12 characters")
    return value


def _load_or_create_signing_key(
    data_dir: Path, *, allow_ephemeral: bool = False
) -> tuple[Ed25519PrivateKey, bool]:
    """Load an encrypted issuer wallet, or create one if a passphrase is configured.

    A process-local ephemeral key is used only by the import-time ASGI app when no
    secrets are configured. Its mutating endpoints remain disabled.
    """
    direct_key = os.environ.get("SKILLCRED_PRIVATE_KEY_B64")
    if direct_key:
        # Explicit secret-manager injection remains supported for controlled deployments.
        return private_key_from_base64(direct_key), True

    wallet_path = data_dir / "issuer-wallet.scw"
    legacy_path = data_dir / "issuer-private-key.b64"
    passphrase = _read_passphrase()

    if legacy_path.exists():
        if not passphrase:
            raise RuntimeError(
                "Legacy plaintext key found; configure SKILLCRED_KEY_PASSPHRASE or "
                "SKILLCRED_KEY_PASSPHRASE_FILE to encrypt it during migration"
            )
        key = private_key_from_base64(legacy_path.read_text(encoding="ascii").strip())
        if wallet_path.exists():
            encrypted_wallet = load_wallet(wallet_path, passphrase)
            encrypted_key = private_key_from_base64(str(encrypted_wallet["private_key"]))
            if identity_from_private_key(encrypted_key).did != identity_from_private_key(key).did:
                raise RuntimeError("Legacy key differs from existing encrypted wallet; refusing ambiguous migration")
        else:
            save_wallet(
                wallet_path,
                wallet_from_key(key, os.getenv("SKILLCRED_ISSUER_NAME", "SkillCred Local Issuer")),
                passphrase,
            )
        legacy_path.unlink()
        return key, True

    if wallet_path.exists():
        if not passphrase:
            raise RuntimeError("Encrypted issuer wallet exists; configure its passphrase secret")
        wallet = load_wallet(wallet_path, passphrase)
        return private_key_from_base64(str(wallet["private_key"])), True

    if not passphrase:
        if allow_ephemeral:
            return generate_keypair(), False
        raise RuntimeError(
            "Configure SKILLCRED_KEY_PASSPHRASE or SKILLCRED_KEY_PASSPHRASE_FILE "
            "before starting the issuer API"
        )
    key = generate_keypair()
    issuer_name = os.getenv("SKILLCRED_ISSUER_NAME", "SkillCred Local Issuer")
    save_wallet(wallet_path, wallet_from_key(key, issuer_name), passphrase)
    return key, True


def _role_for_request(request: Request, required: str, scope: str | None = None) -> str:
    authorization = request.headers.get("authorization")
    compact = extract_bearer(authorization)
    registry: ClientRegistry | None = getattr(request.app.state, "client_registry", None)
    required_scope = scope or {
        "issuer": "credential:issue",
        "revoker": "credential:revoke",
        "verifier": "credential:verify",
        "admin": "*",
    }.get(required, "*")
    if registry is not None and compact and compact.count(".") == 2:
        try:
            claims = registry.authenticate(compact, required, required_scope)
            request.state.principal = claims.get("sub")
            request.state.auth_role = "admin" if "admin" in claims.get("roles", []) else required
            request.state.auth_scopes = claims.get("scope", "").split()
            return request.state.auth_role
        except TokenRejected:
            # A compact token that fails JWT validation may still be a configured
            # static bootstrap token; it must independently pass the legacy check.
            pass
        except ClientRegistryError as exc:
            raise HTTPException(status_code=503, detail="Client registry is unavailable") from exc
    try:
        token_config: TokenConfig = load_token_config()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    role = require_role(authorization, required, config=token_config)
    request.state.principal = "static-bootstrap"
    request.state.auth_role = role
    request.state.auth_scopes = ["*"]
    return role


def _read_client_store_passphrase() -> str | None:
    direct = os.environ.get("SKILLCRED_CLIENT_STORE_PASSPHRASE")
    secret_file = os.environ.get("SKILLCRED_CLIENT_STORE_PASSPHRASE_FILE")
    if direct:
        if len(direct) < 12:
            raise RuntimeError("Client registry passphrase must contain at least 12 characters")
        return direct
    if secret_file:
        path = Path(secret_file).expanduser()
        try:
            stat = path.stat()
            if os.name != "nt" and stat.st_mode & 0o077:
                raise RuntimeError("Client registry secret file must not be readable by group or others")
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise RuntimeError("Could not read client registry passphrase secret file") from exc
        if len(value) < 12:
            raise RuntimeError("Client registry passphrase must contain at least 12 characters")
        return value
    return _read_passphrase()


def create_app(
    data_dir: str | Path | None = None,
    *,
    allow_ephemeral: bool = False,
    rate_limit: int | None = None,
    rate_window_seconds: int | None = None,
) -> FastAPI:
    configured_directory = data_dir or os.environ.get("SKILLCRED_DATA_DIR", "skillcred-data")
    resolved_dir = Path(configured_directory).expanduser().resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        # This directory contains security state and impact records; default to
        # owner-only access rather than inheriting permissive umask/mount modes.
        os.chmod(resolved_dir, 0o700)
    try:
        key, persistent_key = _load_or_create_signing_key(resolved_dir, allow_ephemeral=allow_ephemeral)
    except (RuntimeError, WalletError, ValueError) as exc:
        raise RuntimeError(f"SkillCred signing key initialization failed: {exc}") from exc
    issuer_name = os.environ.get("SKILLCRED_ISSUER_NAME", "SkillCred Local Issuer")
    issuer_id = identity_from_private_key(key).did
    status_url = os.environ.get("SKILLCRED_STATUS_LIST_URL", "https://issuer.example/status-list")
    manager = StatusListManager(resolved_dir, key, issuer_name, status_url)
    metrics = MetricsBundle.create()
    impact_store = ImpactStore(resolved_dir / "impact.sqlite3")
    issuer_trust_store = IssuerTrustStore(resolved_dir / "trusted-issuers.json")
    client_registry = None
    try:
        registry_passphrase = _read_client_store_passphrase() if persistent_key else None
        if registry_passphrase:
            client_registry = ClientRegistry(
                resolved_dir / "clients.enc", registry_passphrase, key
            )
    except (RuntimeError, ClientRegistryError) as exc:
        raise RuntimeError(f"SkillCred client registry initialization failed: {exc}") from exc

    docs_enabled = os.environ.get("SKILLCRED_ENABLE_API_DOCS", "false").lower() == "true"
    application = FastAPI(
        title="SkillCred API",
        version="0.3.0",
        description="Local-first pilot API for issuing and verifying skill credentials.",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    application.state.data_dir = resolved_dir
    application.state.issuer_key = key
    application.state.status_manager = manager
    application.state.issuer_id = issuer_id
    application.state.signing_key_persistent = persistent_key
    application.state.metrics = metrics
    application.state.client_registry = client_registry
    application.state.impact_store = impact_store
    application.state.issuer_trust_store = issuer_trust_store
    application.add_middleware(
        RateLimitMiddleware, limit=rate_limit, window_seconds=rate_window_seconds
    )
    application.add_middleware(RequestSizeLimitMiddleware)

    @application.exception_handler(StarletteHTTPException)
    async def localized_http_exception(request: Request, exc: StarletteHTTPException):
        messages = {
            "Bearer token required": "bearer_required",
            "Invalid bearer token": "bad_token",
            "Insufficient role": "role_denied",
            "Rate limit exceeded": "rate_limit",
        }
        detail = exc.detail
        if isinstance(detail, str) and detail in messages:
            detail = translate(messages[detail], getattr(request.state, "language", None))
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": detail},
            headers=exc.headers,
        )

    @application.middleware("http")
    async def instrument_requests(request: Request, call_next):
        request.state.language = language_from_accept_header(request.headers.get("accept-language"))
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            route_name = getattr(route, "path", "/unmatched")
            metrics.requests.labels(request.method, route_name, "500").inc()
            metrics.request_latency.labels(request.method, route_name).observe(elapsed)
            metrics.errors.labels("unhandled_exception").inc()
            raise
        elapsed = time.perf_counter() - started
        route = request.scope.get("route")
        route_name = getattr(route, "path", "/unmatched")
        metrics.requests.labels(request.method, route_name, str(response.status_code)).inc()
        metrics.request_latency.labels(request.method, route_name).observe(elapsed)
        if response.status_code >= 400:
            metrics.errors.labels(f"http_{response.status_code}").inc()
        return response

    @application.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "skillcred",
            "version": "0.3.0",
            "signing_ready": persistent_key,
        }

    @application.get("/ready", include_in_schema=False)
    def ready() -> dict[str, Any]:
        if not persistent_key:
            raise HTTPException(status_code=503, detail="Persistent signing key is not configured")
        return {"ready": True, "signing_ready": True}

    @application.get("/metrics", include_in_schema=False)
    def prometheus_metrics() -> PlainTextResponse:
        return PlainTextResponse(
            metrics.render().decode("utf-8"),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @application.post("/issue")
    def issue(request: Request, payload: IssueRequest) -> dict[str, Any]:
        if not persistent_key:
            raise HTTPException(status_code=503, detail="Signing is disabled until an encrypted issuer key is configured")
        _role_for_request(request, "issuer")
        try:
            status_entry = manager.allocate()
            credential = create_credential(
                key,
                issuer_name=issuer_name,
                achievement_name=payload.achievement_name,
                achievement_description=payload.achievement_description,
                subject_id=payload.subject_id,
                credential_status=status_entry,
                evidence_url=payload.evidence_url,
            )
            metrics.operations.labels("issue", "success").inc()
            return credential
        except (ValueError, StatusListError) as exc:
            metrics.operations.labels("issue", "failure").inc()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/verify")
    def verify(request: Request, payload: VerifyRequest) -> dict[str, Any]:
        _role_for_request(request, "verifier")
        status_list = payload.status_list_credential
        if status_list is None and payload.credential.get("credentialStatus"):
            try:
                status_list = manager.create_credential()
            except StatusListError as exc:
                metrics.operations.labels("verify", "failure").inc()
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        result = verify_credential(payload.credential, status_list_credential=status_list)
        metrics.operations.labels("verify", "success" if result.get("valid") else "invalid").inc()
        return result

    @application.get("/status-list")
    def status_list() -> dict[str, Any]:
        if not persistent_key:
            raise HTTPException(
                status_code=503,
                detail="Status-list publication is disabled until an encrypted issuer key is configured",
            )
        try:
            return manager.create_credential()
        except StatusListError as exc:
            metrics.errors.labels("status_list").inc()
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @application.post("/revoke")
    def revoke(request: Request, payload: RevokeRequest) -> dict[str, Any]:
        if not persistent_key:
            raise HTTPException(status_code=503, detail="Signing is disabled until an encrypted issuer key is configured")
        _role_for_request(request, "revoker")
        try:
            manager.revoke(payload.status_list_index)
            metrics.operations.labels("revoke", "success").inc()
            return {"revoked": True, "status_list_index": payload.status_list_index}
        except StatusListError as exc:
            metrics.operations.labels("revoke", "failure").inc()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/clients", status_code=201)
    def create_client(request: Request, payload: ClientCreateRequest) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        try:
            return registry.register_client(payload.name, payload.roles, payload.scopes)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.get("/admin/clients")
    def list_clients(request: Request) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        return {"clients": registry.list_clients()}

    @application.post("/admin/clients/{client_id}/tokens")
    def issue_client_token(request: Request, client_id: str, payload: ClientTokenRequest) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        try:
            return registry.issue_token(client_id, payload.expires_in, payload.scopes)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/clients/{client_id}/rotate")
    def rotate_client_token(request: Request, client_id: str, payload: ClientTokenRequest) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        try:
            return registry.rotate_token(client_id, payload.expires_in)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/clients/{client_id}/revoke")
    def revoke_client(request: Request, client_id: str) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        try:
            registry.revoke_client(client_id)
            return {"revoked": True, "client_id": client_id}
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/tokens/{jti}/revoke")
    def revoke_client_token(request: Request, jti: str) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(status_code=503, detail="Encrypted client registry is not configured")
        try:
            registry.revoke_token(jti)
            return {"revoked": True, "jti": jti}
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/metrics/impact", status_code=201)
    def record_impact(request: Request, payload: ImpactRecordRequest) -> dict[str, Any]:
        _role_for_request(request, "verifier", "impact:write")
        try:
            record_id = impact_store.add(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        metrics.operations.labels("impact_record", "success").inc()
        return {"recorded": True, "record_id": record_id}

    @application.get("/metrics/impact")
    def get_impact(request: Request, format: str = "json"):
        _role_for_request(request, "admin")
        if format == "csv":
            from fastapi.responses import Response as CsvResponse
            return CsvResponse(
                content=impact_store.export_csv(), media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": "attachment; filename=skillcred-impact.csv"},
            )
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be json or csv")
        return {"summary": impact_store.summary(), "export": json.loads(impact_store.export_json())}

    @application.get("/issuer")
    def issuer() -> dict[str, str]:
        return {"id": issuer_id, "name": issuer_name}

    @application.get("/.well-known/skillcred-issuer.json", include_in_schema=False)
    def issuer_discovery() -> dict[str, Any]:
        # Discovery is intentionally informational: clients must pin the issuer DID
        # out of band and must not infer trust merely because metadata is reachable.
        return create_issuer_metadata(
            issuer_id=issuer_id,
            name=issuer_name,
            status_list_url=status_url,
            version="0.3.0",
        )

    @application.get("/admin/federation/pins")
    def list_issuer_pins(request: Request) -> dict[str, Any]:
        _role_for_request(request, "admin")
        return {"issuers": issuer_trust_store.list_pins()}

    @application.post("/admin/federation/pins", status_code=201)
    def pin_issuer(request: Request, payload: IssuerPinRequest) -> dict[str, Any]:
        _role_for_request(request, "admin")
        try:
            record = issuer_trust_store.pin(
                payload.metadata, payload.expected_issuer_id, operator_note=payload.operator_note
            )
        except FederationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"pinned": True, "issuer": record}

    @application.delete("/admin/federation/pins/{issuer_id}")
    def unpin_issuer(request: Request, issuer_id: str) -> dict[str, Any]:
        _role_for_request(request, "admin")
        try:
            issuer_trust_store.unpin(issuer_id)
        except FederationError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"pinned": False, "issuer_id": issuer_id}

    return application


# Importing the ASGI object remains safe in an unconfigured checkout. When no
# secrets are configured, keep its degraded ephemeral state in a fresh temporary
# directory instead of colliding with a persistent issuer's state files.
def _default_app_data_dir() -> Path:
    has_secret = bool(
        os.environ.get("SKILLCRED_KEY_PASSPHRASE")
        or os.environ.get("SKILLCRED_KEY_PASSPHRASE_FILE")
        or os.environ.get("SKILLCRED_PRIVATE_KEY_B64")
    )
    if has_secret:
        return Path(os.environ.get("SKILLCRED_DATA_DIR", "skillcred-data"))
    return Path(tempfile.mkdtemp(prefix="skillcred-ephemeral-api-"))


app = create_app(data_dir=_default_app_data_dir(), allow_ephemeral=True)
