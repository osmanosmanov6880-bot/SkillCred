"""Local-first issuer API with role tokens, rate limiting and encrypted signing keys."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from skillcred.auth import TokenConfig, extract_bearer, load_token_config, require_role
from skillcred.badge import create_credential
from skillcred.client_registry import ClientRegistry, ClientRegistryError, TokenRejected
from skillcred.demo_registry import DemoCredentialRegistry
from skillcred.federation import FederationError, IssuerTrustStore, create_issuer_metadata
from skillcred.i18n import language_from_accept_header, translate
from skillcred.impact import ImpactRecordRequest, ImpactStore
from skillcred.keys import (
    generate_keypair,
    identity_from_private_key,
    private_key_from_base64,
)
from skillcred.metrics import MetricsBundle
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
                raise RuntimeError(
                    "Legacy key differs from existing encrypted wallet; refusing ambiguous migration"
                )
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


def _load_or_create_demo_signing_key(
    data_dir: Path, issuer_name: str
) -> tuple[Ed25519PrivateKey, bool]:
    """Load or create a separate encrypted key for public demo credentials.

    The demo issuer never uses the production issuer's signing key. An optional
    DEMO_ISSUER_PRIVATE_KEY_B64 secret can be injected explicitly; otherwise the
    dedicated wallet is encrypted using the configured SkillCred wallet passphrase.
    """
    direct_key = os.environ.get("DEMO_ISSUER_PRIVATE_KEY_B64")
    if direct_key:
        return private_key_from_base64(direct_key), True

    wallet_path = data_dir / "demo-issuer-wallet.scw"
    passphrase = _read_passphrase()
    if wallet_path.exists():
        if not passphrase:
            raise RuntimeError(
                "Demo issuer wallet exists; configure SKILLCRED_KEY_PASSPHRASE "
                "to unlock it"
            )
        wallet = load_wallet(wallet_path, passphrase)
        return private_key_from_base64(str(wallet["private_key"])), True

    if not passphrase:
        # Do not create a process-local demo key: it would make the issuer DID
        # unstable and invalidate previously issued demo credentials on restart.
        return generate_keypair(), False

    key = generate_keypair()
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
                raise RuntimeError(
                    "Client registry secret file must not be readable by group or others"
                )
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
        key, persistent_key = _load_or_create_signing_key(
            resolved_dir, allow_ephemeral=allow_ephemeral
        )
    except (RuntimeError, WalletError, ValueError) as exc:
        raise RuntimeError(f"SkillCred signing key initialization failed: {exc}") from exc
    issuer_name = os.environ.get("SKILLCRED_ISSUER_NAME", "SkillCred Local Issuer")
    issuer_id = identity_from_private_key(key).did
    status_url = os.environ.get("SKILLCRED_STATUS_LIST_URL", "https://issuer.example/status-list")
    manager = StatusListManager(resolved_dir, key, issuer_name, status_url)
    demo_issuer_name = os.environ.get("SKILLCRED_DEMO_ISSUER_NAME", "SkillCred Public Demo")
    demo_token = os.environ.get("DEMO_ISSUER_TOKEN", "")
    demo_key: Ed25519PrivateKey | None = None
    demo_manager: StatusListManager | None = None
    demo_key_persistent = False
    demo_enabled = len(demo_token) >= 32 and persistent_key
    if demo_enabled:
        demo_key, demo_key_persistent = _load_or_create_demo_signing_key(
            resolved_dir, demo_issuer_name
        )
        if demo_key_persistent:
            public_base_url = os.environ.get(
                "RENDER_EXTERNAL_URL", "https://skillcred-pilot-api.onrender.com"
            ).rstrip("/")
            demo_status_url = os.environ.get(
                "DEMO_STATUS_LIST_URL", public_base_url + "/demo/status-list"
            )
            demo_manager = StatusListManager(
                resolved_dir / "demo-status",
                demo_key,
                demo_issuer_name,
                demo_status_url,
            )
    metrics = MetricsBundle.create()
    impact_store = ImpactStore(resolved_dir / "impact.sqlite3")
    issuer_trust_store = IssuerTrustStore(resolved_dir / "trusted-issuers.json")
    client_registry = None
    try:
        registry_passphrase = _read_client_store_passphrase() if persistent_key else None
        if registry_passphrase:
            client_registry = ClientRegistry(resolved_dir / "clients.enc", registry_passphrase, key)
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
    application.state.demo_registry = DemoCredentialRegistry(resolved_dir / "demo-credentials.sqlite3")
    application.state.demo_issuer_name = demo_issuer_name
    application.state.demo_issuer_key = demo_key
    application.state.demo_status_manager = demo_manager
    application.state.demo_enabled = bool(demo_enabled and demo_key_persistent and demo_manager)
    # The public landing page is hosted on OSGARD; allow only that origin to call
    # the deliberately narrow demo routes. No bearer-token headers are exposed.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://osgard.world",
            "https://www.osgard.world",
            "http://localhost:4173",
            "http://localhost:4188",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Accept", "Content-Type"],
        max_age=600,
    )
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

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def homepage() -> HTMLResponse:
        static_homepage = Path(__file__).parent / "static" / "index.html"
        if static_homepage.is_file():
            return HTMLResponse(content=static_homepage.read_text(encoding="utf-8"))
        page = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#090b10">
<meta name="description" content="SkillCred — открытая инфраструктура цифровых подтверждений практических навыков. Подписывайте, переносите и независимо проверяйте доказательства навыков.">
<title>SkillCred — доказательства навыков, которым можно доверять</title>
<style>
:root{color-scheme:dark;--bg:#090b10;--panel:#10141c;--panel2:#151a24;--line:#2a303a;--text:#f4f0e8;--muted:#a9adb7;--gold:#d7bd89;--gold2:#f0dfb8;--cyan:#98d9df;--good:#a8d8b2;--max:1180px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:100px}body{margin:0;background:radial-gradient(ellipse at 80% 0%,#26304166 0,transparent 35%),radial-gradient(ellipse at 5% 22%,#d7bd890b 0,transparent 27%),var(--bg);color:var(--text);line-height:1.6}a{color:inherit}button,a{touch-action:manipulation}a:focus-visible,button:focus-visible{outline:3px solid var(--cyan);outline-offset:4px}button{font:inherit}
.wrap{width:min(var(--max),calc(100% - 48px));margin-inline:auto}.topline{border-bottom:1px solid #ffffff12;color:#b6b3ac;font-size:11px;letter-spacing:.16em;text-transform:uppercase}.topline .wrap{min-height:36px;display:flex;justify-content:space-between;align-items:center;gap:12px}.online-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--good);box-shadow:0 0 12px #a8d8b280;margin-right:8px}
header{position:sticky;top:0;z-index:10;background:#090b10e8;backdrop-filter:blur(18px);border-bottom:1px solid #ffffff12}.nav{height:78px;display:flex;align-items:center;justify-content:space-between;gap:24px}.brand{display:flex;align-items:center;gap:12px;text-decoration:none;flex-shrink:0}.brand-mark{width:39px;height:39px;border:1px solid #d7bd8970;border-radius:12px;display:grid;place-items:center;color:var(--gold2);font-family:Georgia,serif;font-size:24px;box-shadow:inset 0 0 20px #d7bd8910}.brand-name{font-size:17px;letter-spacing:.17em;font-weight:760}.brand-sub{display:block;color:#9296a0;font-size:9px;letter-spacing:.17em;text-transform:uppercase;margin-top:-3px}.navlinks{display:flex;align-items:center;gap:24px}.navlinks a{font-size:12px;text-decoration:none;color:#c3c4c8;transition:color .2s}.navlinks a:hover{color:var(--gold2)}.nav-cta,.btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;text-decoration:none;border:1px solid #48433a;border-radius:4px;padding:12px 17px;min-height:46px;font-size:12px;font-weight:700;letter-spacing:.02em;transition:transform .2s,border-color .2s,background .2s}.nav-cta{min-height:40px;padding:9px 14px;color:var(--gold2)}.btn:hover,.nav-cta:hover{transform:translateY(-1px);border-color:var(--gold)}.btn.primary{background:var(--gold);color:#15140f;border-color:var(--gold)}.btn.secondary{background:#ffffff04;color:var(--text)}.btn.text{border-color:transparent;color:#d9d5ca;padding-inline:8px}
.hero{padding:88px 0 72px;display:grid;grid-template-columns:1.07fr .93fr;gap:64px;align-items:center;min-height:610px}.eyebrow{display:flex;align-items:center;gap:12px;font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);font-weight:750}.eyebrow:before{content:"";width:28px;height:1px;background:var(--gold)}h1,h2,h3,p{margin-top:0}h1{font-size:clamp(42px,5.5vw,73px);font-weight:520;letter-spacing:-.055em;line-height:1.04;margin:24px 0}.h1-accent{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-style:italic;color:var(--gold2)}.hero-copy{max-width:570px;font-size:17px;color:#b8bbc3;line-height:1.85}.actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:30px}.microline{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:27px;color:#8d929e;font-size:11px}.microline span+span:before{content:"·";margin-right:12px;color:var(--gold)}
.art-stage{position:relative;min-height:440px;display:grid;place-items:center;isolation:isolate}.orb{position:absolute;width:340px;height:340px;border:1px solid #d7bd8923;border-radius:50%;box-shadow:0 0 70px #d7bd8908,inset 0 0 70px #d7bd8908}.orb:before,.orb:after{content:"";position:absolute;border:1px solid #d7bd891c;border-radius:50%;inset:25px}.orb:after{inset:52px}.halo{position:absolute;width:410px;height:210px;border:1px solid #98d9df22;transform:rotate(-31deg);border-radius:50%}.credential-card{position:relative;width:min(100%,365px);min-height:354px;padding:28px;background:linear-gradient(140deg,#1d222b,#10141c 66%);border:1px solid #a58d5a72;box-shadow:0 35px 100px #000b,0 0 80px #d7bd8908;transform:rotate(2deg);z-index:1}.credential-card:before{content:"";position:absolute;inset:7px;border:1px solid #d7bd891e;pointer-events:none}.card-top{display:flex;justify-content:space-between;align-items:center;color:var(--gold);font-size:9px;letter-spacing:.18em;text-transform:uppercase}.seal{width:47px;height:47px;border:1px solid #d7bd8980;border-radius:50%;display:grid;place-items:center;color:var(--gold2);font:25px Georgia,serif}.card-rule{height:1px;background:linear-gradient(90deg,var(--gold),transparent);margin:25px 0}.card-kicker{font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:#969ba5}.card-title{font:31px/1.12 Georgia,"Times New Roman",serif;margin:11px 0 8px;max-width:240px}.card-desc{font-size:11px;line-height:1.6;color:#a9adb7;max-width:260px}.card-bottom{display:flex;align-items:end;justify-content:space-between;margin-top:27px;gap:12px}.fingerprint{font:9px/1.8 ui-monospace,SFMono-Regular,monospace;color:#8f9b9d;word-break:break-all;max-width:190px}.verified{font-size:10px;text-align:right;color:var(--good);white-space:nowrap}.verified b{display:block;font-size:12px;font-weight:650}.floating-tag{position:absolute;z-index:2;display:flex;align-items:center;gap:10px;padding:11px 14px;border:1px solid #333b43;background:#0b0e14eF;box-shadow:0 14px 40px #0008;font-size:10px;color:#d4d5d7;letter-spacing:.04em}.floating-tag .tiny-dot{width:7px;height:7px;border-radius:50%;background:var(--cyan)}.tag-a{right:-4px;top:84px}.tag-b{left:-9px;bottom:73px}.art-caption{position:absolute;bottom:2px;color:#797e89;font-size:9px;letter-spacing:.16em;text-transform:uppercase;text-align:center}
.strip{border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#ffffff02}.strip .wrap{display:grid;grid-template-columns:repeat(4,1fr)}.metric{padding:24px 16px;border-right:1px solid var(--line)}.metric:first-child{padding-left:0}.metric:last-child{border-right:0}.metric b{display:block;color:var(--gold2);font:22px Georgia,serif;font-weight:400}.metric span{display:block;color:#8e939e;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-top:5px}
.section{padding:94px 0}.section-head{display:grid;grid-template-columns:.7fr 1fr;gap:60px;align-items:end;margin-bottom:40px}.section-index{font:13px Georgia,serif;color:var(--gold);letter-spacing:.12em}.section h2{font-size:clamp(30px,4vw,48px);font-weight:500;letter-spacing:-.045em;line-height:1.12;margin:14px 0 0}.section h2 em{font-family:Georgia,serif;font-weight:400;color:var(--gold2)}.section-intro{max-width:580px;color:#a9adb7;line-height:1.85;font-size:14px;margin:0}.feature-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.feature{padding:27px 25px 24px;border:1px solid var(--line);background:linear-gradient(145deg,#171b23,#0e1117);min-height:232px}.feature-number{color:var(--gold);font:14px Georgia,serif}.feature h3{font-size:17px;font-weight:600;margin:27px 0 10px}.feature p{color:#a8acb5;font-size:13px;line-height:1.8;margin-bottom:0}.audience-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.audience{padding:22px 20px;border-top:1px solid #786844;background:#11151c}.audience .symbol{font:23px Georgia,serif;color:var(--gold);margin-bottom:26px}.audience h3{font-size:15px;margin-bottom:8px}.audience p{color:#9da2ad;font-size:12px;line-height:1.75;margin:0}
.band{background:linear-gradient(105deg,#161a20,#11151b);border-block:1px solid var(--line)}.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:0}.step{padding:25px 24px;border-left:1px solid var(--line)}.step:first-child{border-left:0;padding-left:0}.step .n{font:13px Georgia,serif;color:var(--gold)}.step h3{font-size:15px;margin:18px 0 8px}.step p{font-size:12px;color:#a5a9b3;line-height:1.8;margin:0}
.business-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.business-card{padding:25px;border:1px solid var(--line);background:#11151c}.business-card .type{font-size:9px;letter-spacing:.18em;color:var(--gold);text-transform:uppercase}.business-card h3{font-size:18px;font-weight:600;margin:13px 0 8px}.business-card p{font-size:13px;color:#a9adb7;line-height:1.8;margin-bottom:0}.business-note{margin-top:18px;border-left:2px solid var(--gold);padding:12px 15px;background:#d7bd890b;color:#b8b3a7;font-size:12px;line-height:1.8}
.trust-grid{display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:start}.trust-list{display:grid;gap:0}.trust-row{padding:18px 0;border-bottom:1px solid var(--line);display:grid;grid-template-columns:27px 1fr;gap:12px}.trust-row .tick{color:var(--cyan);font-size:15px}.trust-row strong{display:block;font-size:13px;font-weight:600;margin-bottom:4px}.trust-row span{font-size:12px;color:#a1a6b0;line-height:1.75}.pilot-box{padding:27px;border:1px solid #6b5b3c;background:linear-gradient(145deg,#171811,#11151a)}.pilot-box h3{font:26px Georgia,serif;color:var(--gold2);margin:15px 0 10px}.pilot-box p{font-size:13px;color:#b4b4ad;line-height:1.8}.status-panel{margin-top:18px;border:1px solid var(--line);background:#0a0d12;padding:18px}.status-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.status-head strong{font-size:12px}.status-label{color:#89919a;font-size:10px}.status-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:14px}.check-button{background:#d7bd89;color:#15140f;border:0;border-radius:3px;padding:10px 13px;font-weight:750;font-size:11px;cursor:pointer}.check-button:disabled{opacity:.65;cursor:wait}.status-result{font-size:11px;color:#aab0b8;line-height:1.8;margin:12px 0 0;white-space:pre-line}.status-result.ok{color:var(--good)}.status-result.fail{color:#f2a7a7}
.final-cta{padding:75px 0;background:radial-gradient(ellipse at 70% 40%,#d7bd8910,transparent 38%),#0e1117;border-top:1px solid var(--line)}.cta-inner{display:flex;align-items:center;justify-content:space-between;gap:36px}.cta-inner h2{font:clamp(30px,4vw,45px)/1.15 Georgia,serif;font-weight:400;margin:12px 0}.cta-inner p{font-size:13px;color:#9fa4ae;max-width:580px;margin:0}.cta-actions{display:flex;gap:10px;flex-wrap:wrap;flex-shrink:0}
footer{padding:28px 0 36px;border-top:1px solid var(--line);color:#777e89;font-size:11px}.footer-inner{display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap}.footer-links{display:flex;gap:18px;flex-wrap:wrap}.footer-links a{color:#a4a8b0;text-decoration:none}.footer-links a:hover{color:var(--gold2)}.disclaimer{max-width:750px;color:#858b95;font-size:10px;line-height:1.8;margin-top:18px}
@media(max-width:900px){.navlinks{gap:13px}.navlinks a{font-size:11px}.hero{gap:26px;padding-top:60px}.art-stage{min-height:390px}.orb{width:290px;height:290px}.halo{width:330px}.tag-a{right:-1px}.tag-b{left:-1px}.audience-grid{grid-template-columns:repeat(2,1fr)}.steps{grid-template-columns:repeat(2,1fr);row-gap:25px}.step:nth-child(3){border-left:0;padding-left:0}}
@media(max-width:680px){.wrap{width:min(var(--max),calc(100% - 32px))}.topline .wrap{font-size:9px}.topline .right-note{display:none}.nav{height:68px}.navlinks{display:none}.brand-name{font-size:15px}.nav-cta{font-size:10px}.hero{grid-template-columns:1fr;padding:61px 0 42px;gap:20px;min-height:auto}.hero-copy{font-size:15px}.hero h1{font-size:48px}.art-stage{min-height:375px;margin-top:0}.credential-card{width:min(88%,340px);min-height:335px;padding:24px}.orb{width:270px;height:270px}.tag-a{top:44px;right:0}.tag-b{bottom:49px;left:0}.art-caption{font-size:8px}.strip .wrap{grid-template-columns:repeat(2,1fr)}.metric{padding:18px 12px;border-bottom:1px solid var(--line)}.metric:nth-child(2){border-right:0}.metric:nth-child(3){padding-left:0;border-bottom:0}.metric:nth-child(4){border-right:0;border-bottom:0}.section{padding:64px 0}.section-head{grid-template-columns:1fr;gap:18px;margin-bottom:26px}.section h2{font-size:35px}.feature-grid{grid-template-columns:1fr}.feature{min-height:auto;padding:22px}.feature h3{margin-top:18px}.audience-grid{grid-template-columns:1fr 1fr;gap:9px}.audience{padding:17px 14px}.audience .symbol{margin-bottom:17px}.steps{grid-template-columns:1fr;row-gap:0}.step,.step:first-child,.step:nth-child(3){padding:18px 0 18px 18px;border-left:1px solid var(--line)}.step:first-child{padding-top:0}.business-grid,.trust-grid{grid-template-columns:1fr;gap:15px}.cta-inner{display:block}.cta-actions{margin-top:23px}.cta-actions .btn{flex:1}.final-cta{padding:56px 0}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*:before,*:after{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="topline"><div class="wrap"><span><i class="online-dot" aria-hidden="true"></i>Открытая инфраструктура доверия</span><span class="right-note">Пилотная версия 0.3.0 · Apache-2.0</span></div></div>
<header><div class="wrap nav">
<a class="brand" href="/" aria-label="SkillCred — на главную"><span class="brand-mark" aria-hidden="true">S</span><span><span class="brand-name">SKILLCRED</span><span class="brand-sub">Proof of practical skill</span></span></a>
<nav class="navlinks" aria-label="Главная навигация"><a href="#how">Как работает</a><a href="#who">Кому полезно</a><a href="#business">Модель бизнеса</a><a href="#trust">Безопасность</a><!-- API_DOCS_LINK --></nav>
<a class="nav-cta" href="https://github.com/osmanosmanov6880-bot/SkillCred" target="_blank" rel="noopener noreferrer">Изучить исходный код ↗</a>
</div></header>
<main>
<section class="wrap hero" aria-labelledby="hero-title">
<div>
<div class="eyebrow">Навыки, которые можно подтвердить</div>
<h1 id="hero-title">Не просто сертификат.<br><span class="h1-accent">Доказательство навыка.</span></h1>
<p class="hero-copy">SkillCred помогает организациям выдавать цифровые подтверждения практических навыков, которые можно переносить между платформами и независимо проверять — без обязательного единого хранилища профилей учащихся.</p>
<div class="actions"><a class="btn primary" href="#how">Узнать, как это работает <span aria-hidden="true">↘</span></a><a class="btn secondary" href="mailto:osman.osmanov6880@gmail.com?subject=SkillCred%20%E2%80%94%20%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5%20%D0%BF%D0%B8%D0%BB%D0%BE%D1%82%D0%B0">Обсудить пилот <span aria-hidden="true">↗</span></a></div>
<div class="microline"><span>Открытый исходный код</span><span>Криптографическая подпись</span><span>Контроль у держателя</span></div>
</div>
<div class="art-stage" aria-label="Иллюстрация переносимого цифрового подтверждения навыка">
<div class="orb" aria-hidden="true"></div><div class="halo" aria-hidden="true"></div>
<div class="credential-card">
<div class="card-top"><span>SkillCred · Credential</span><span class="seal" aria-hidden="true">S</span></div>
<div class="card-rule"></div>
<div class="card-kicker">Практический навык · Демонстрационный макет</div>
<div class="card-title">Безопасная работа</div>
<p class="card-desc">Подтверждение результата оценки, подписанное выдавшей организацией.</p>
<div class="card-rule"></div>
<div class="card-bottom"><div class="fingerprint">ISSUER<br>did:key:…публичный идентификатор</div><div class="verified">◇<b>Подпись</b>проверяема</div></div>
</div>
<div class="floating-tag tag-a"><span class="tiny-dot"></span>Подпись издателя</div>
<div class="floating-tag tag-b"><span class="tiny-dot"></span>Можно перенести</div>
<div class="art-caption">Визуальный пример · Не реальный сертификат</div>
</div>
</section>
<div class="strip"><div class="wrap">
<div class="metric"><b>Выдать</b><span>Подписать результат оценки</span></div>
<div class="metric"><b>Передать</b><span>Хранить у владельца</span></div>
<div class="metric"><b>Проверить</b><span>Проверить целостность</span></div>
<div class="metric"><b>Отозвать</b><span>Обновить статус доверия</span></div>
</div></div>
<section class="section wrap" id="how">
<div class="section-head"><div><div class="section-index">01 / Принцип работы</div><h2>От оценки навыка<br>к <em>проверяемому факту.</em></h2></div><p class="section-intro">SkillCred — не школа и не каталог курсов. Это технологический слой между теми, кто оценивает навык, теми, кто его получил, и теми, кому нужно проверить подтверждение.</p></div>
<div class="feature-grid">
<article class="feature"><span class="feature-number">01 — ОЦЕНКА</span><h3>Организация подтверждает навык</h3><p>Например, учебный центр проверяет практическую работу по технике безопасности. Само решение о компетенции принимает организация, а не программа SkillCred.</p></article>
<article class="feature"><span class="feature-number">02 — ПОДПИСЬ</span><h3>SkillCred создаёт цифровую запись</h3><p>Запись подписывается ключом издателя. Изменение содержимого можно обнаружить при проверке подписи. Владелец может хранить и передавать файл самостоятельно.</p></article>
<article class="feature"><span class="feature-number">03 — ПРОВЕРКА</span><h3>Работодатель проверяет подлинность</h3><p>Проверяющая сторона может проверить подпись и статус отзыва. Подпись подтверждает целостность документа, но сама по себе не доказывает репутацию или законность издателя.</p></article>
</div>
</section>
<section class="section band" id="who"><div class="wrap">
<div class="section-head"><div><div class="section-index">02 / Для кого</div><h2>Когда важно не название курса,<br>а <em>что человек умеет.</em></h2></div><p class="section-intro">Лучший первый сценарий — узкий и понятный: организация оценивает конкретный практический навык, выдаёт подтверждение, а другая сторона проверяет его без долгой ручной переписки.</p></div>
<div class="audience-grid">
<article class="audience"><div class="symbol" aria-hidden="true">01</div><h3>Учебные центры и вузы</h3><p>Выдавайте переносимые подтверждения практических результатов выпускникам и участникам программ.</p></article>
<article class="audience"><div class="symbol" aria-hidden="true">02</div><h3>Работодатели и HR</h3><p>Проверяйте подпись и статус полученного подтверждения вместо доверия только к картинке или PDF.</p></article>
<article class="audience"><div class="symbol" aria-hidden="true">03</div><h3>Онлайн-школы и платформы</h3><p>Добавляйте подтверждения навыков к своему обучающему продукту через API и собственные процессы оценки.</p></article>
<article class="audience"><div class="symbol" aria-hidden="true">04</div><h3>НКО и профессиональные сообщества</h3><p>Документируйте завершённые программы, волонтёрскую подготовку или отраслевые проверки навыков.</p></article>
</div>
</div></section>
<section class="section wrap" id="flow">
<div class="section-head"><div><div class="section-index">03 / Путь подтверждения</div><h2>Четыре шага.<br><em>Без лишней магии.</em></h2></div><p class="section-intro">Технология защищает проверяемость записи. Она не заменяет качественную оценку, правила выдачи или договорённость о том, какие организации считаются надёжными.</p></div>
<div class="steps">
<article class="step"><div class="n">ШАГ 01</div><h3>Оценить</h3><p>Проверить навык по известным критериям и зафиксировать решение.</p></article>
<article class="step"><div class="n">ШАГ 02</div><h3>Выдать</h3><p>Уполномоченный издатель создаёт подписанное цифровое подтверждение.</p></article>
<article class="step"><div class="n">ШАГ 03</div><h3>Передать</h3><p>Владелец сохраняет файл у себя и передаёт его тому, кому сам решит.</p></article>
<article class="step"><div class="n">ШАГ 04</div><h3>Проверить статус</h3><p>Проверяющий проверяет подпись и актуальный статус, включая отзыв.</p></article>
</div>
</section>
<section class="section band" id="business"><div class="wrap">
<div class="section-head"><div><div class="section-index">04 / Устойчивая модель</div><h2>Открытый код.<br><em>Платная ценность вокруг него.</em></h2></div><p class="section-intro">Монетизировать стоит не сам факт существования открытого стандарта, а удобство внедрения, надёжность эксплуатации, сопровождение и интеграции. Это направления бизнес-модели, а не уже работающие тарифы.</p></div>
<div class="business-grid">
<article class="business-card"><div class="type">Модель 01 · Внедрение</div><h3>Платная установка и настройка</h3><p>Развернуть SkillCred в инфраструктуре клиента, настроить издателя, ключи, резервное копирование, доступы и процесс отзыва.</p></article>
<article class="business-card"><div class="type">Модель 02 · Подписка</div><h3>Размещённый сервис для организаций</h3><p>В перспективе — платный управляемый кабинет: управление командами и издателями, журналы аудита, резервирование и обслуживание.</p></article>
<article class="business-card"><div class="type">Модель 03 · Интеграция</div><h3>Подключение к системам клиента</h3><p>Интеграция API с LMS, HR-системами, порталами выпускников и внутренними процессами проверки навыков.</p></article>
<article class="business-card"><div class="type">Модель 04 · Сопровождение</div><h3>Поддержка и SLA</h3><p>Обновления, мониторинг, обучение команды, политика ключей и помощь с миграцией. Отдельные условия — для больших организаций.</p></article>
</div>
<div class="business-note"><strong>Что реалистично продавать первым:</strong> ограниченный платный пилот внедрения с фиксированным объёмом работ. Не продавать пока «международно признанный сертификат» или «официальную сертификацию»: совместимость и сертификация ещё должны быть доказаны.</div>
</div></section>
<section class="section wrap" id="trust">
<div class="section-head"><div><div class="section-index">05 / Доверие и прозрачность</div><h2>Не просим верить на слово.<br><em>Показываем границы.</em></h2></div><p class="section-intro">SkillCred — экспериментальный пилот для проверки технической и бизнес-гипотезы. Открытый код и успешный тест — полезные признаки, но не эквивалент независимого аудита или официального одобрения стандарта.</p></div>
<div class="trust-grid"><div class="trust-list">
<div class="trust-row"><div class="tick" aria-hidden="true">✓</div><div><strong>Подпись Ed25519</strong><span>Позволяет проверить, что документ соответствует подписанному содержимому и связан с публичным ключом издателя.</span></div></div>
<div class="trust-row"><div class="tick" aria-hidden="true">✓</div><div><strong>Нет обязательной базы всех учащихся</strong><span>Файлы подтверждений можно хранить у владельца. Статус отзыва публикуется отдельно.</span></div></div>
<div class="trust-row"><div class="tick" aria-hidden="true">✓</div><div><strong>Защищённые операции — только с авторизацией</strong><span>Выдача и отзыв через API требуют роль и соответствующие полномочия. Главная страница не просит секретные токены.</span></div></div>
<div class="trust-row"><div class="tick" aria-hidden="true">!</div><div><strong>Ограничения указаны открыто</strong><span>Нет заявления об официальной сертификации 1EdTech; совместимость с независимыми кошельками нужно подтвердить.</span></div></div>
</div>
<aside class="pilot-box"><div class="eyebrow">Проверка вживую</div><h3>Сервис доступен?</h3><p>Нажмите кнопку — страница сама проверит публичные маршруты состояния. Проверка не выдаёт сертификаты и не передаёт данные учащихся.</p>
<div class="status-panel"><div class="status-head"><strong>SkillCred API</strong><span class="status-label">Публичная проверка</span></div><div class="status-actions"><button id="checkHealth" class="check-button" type="button">Проверить сервис ↗</button><a class="status-label" href="/health">Открыть JSON</a></div><p id="healthResult" class="status-result" role="status" aria-live="polite">Проверка ещё не запускалась.</p></div>
<p style="margin-top:17px;font-size:11px">Технические детали и история изменений доступны в открытом репозитории.</p><a class="btn secondary" href="https://github.com/osmanosmanov6880-bot/SkillCred" target="_blank" rel="noopener noreferrer">Код, тесты и ограничения ↗</a></aside>
</div>
</section>
<section class="final-cta"><div class="wrap cta-inner"><div><div class="eyebrow">Следующий шаг</div><h2>Найти один реальный сценарий<br>и доказать его пользу.</h2><p>Ищем учебный центр, работодателя или профессиональное сообщество для небольшого пилота: один навык, один издатель, независимая проверка, измеримые результаты.</p></div><div class="cta-actions"><a class="btn primary" href="mailto:osman.osmanov6880@gmail.com?subject=SkillCred%20%E2%80%94%20%D0%BF%D0%B8%D0%BB%D0%BE%D1%82&body=%D0%97%D0%B4%D1%80%D0%B0%D0%B2%D1%81%D1%82%D0%B2%D1%83%D0%B9%D1%82%D0%B5!%20%D0%A5%D0%BE%D1%87%D1%83%20%D0%BE%D0%B1%D1%81%D1%83%D0%B4%D0%B8%D1%82%D1%8C%20%D0%BF%D0%B8%D0%BB%D0%BE%D1%82%20SkillCred.">Обсудить пилот ↗</a><a class="btn secondary" href="https://github.com/osmanosmanov6880-bot/SkillCred" target="_blank" rel="noopener noreferrer">GitHub ↗</a></div></div></section>
</main>
<footer><div class="wrap"><div class="footer-inner"><a class="brand" href="/" aria-label="SkillCred — на главную"><span class="brand-mark" aria-hidden="true">S</span><span><span class="brand-name">SKILLCRED</span><span class="brand-sub">Open infrastructure</span></span></a><div class="footer-links"><a href="#how">Как работает</a><a href="#business">Бизнес-модель</a><a href="/health">Состояние API</a><a href="/ready">Готовность API</a><a href="https://github.com/osmanosmanov6880-bot/SkillCred" target="_blank" rel="noopener noreferrer">GitHub</a></div></div><p class="disclaimer">SkillCred 0.3.0 · Apache-2.0 · Экспериментальный пилот. Не является сертифицированной реализацией 1EdTech Open Badges 3.0. Криптографическая подпись не подтверждает сама по себе законность издателя или достаточность оценки навыка. Не отправляйте конфиденциальные персональные данные и не полагайтесь на сервис для решений с существенными последствиями.</p></div></footer>
<script>
(function(){
  var button=document.getElementById("checkHealth");
  var result=document.getElementById("healthResult");
  if(!button||!result){return;}
  button.addEventListener("click",async function(){
    button.disabled=true;
    button.textContent="Проверяем…";
    result.className="status-result";
    result.textContent="Запрашиваем /health и /ready. Это может занять несколько секунд.";
    try{
      var paths=["/health","/ready"];
      var checks=await Promise.all(paths.map(async function(path){
        var response=await fetch(path,{method:"GET",cache:"no-store",headers:{"Accept":"application/json"}});
        var body=await response.json().catch(function(){return {};});
        return {path:path,ok:response.ok,status:response.status,body:body};
      }));
      var allOk=checks.every(function(item){return item.ok;});
      result.className="status-result "+(allOk?"ok":"fail");
      result.textContent=checks.map(function(item){
        return (item.ok?"✓ ":"✕ ")+item.path+" — HTTP "+item.status+(item.body.service?" · "+item.body.service+" v"+item.body.version:"");
      }).join("\n")+(allOk?"\nСервис отвечает. Это проверка доступности, не полная сертификация.":"\nОдин или несколько маршрутов не прошли проверку. Смотрите статус сервиса и журналы запуска.");
    }catch(error){
      result.className="status-result fail";
      result.textContent="Не удалось связаться с API. Проверьте соединение и повторите попытку. Техническая ошибка: "+(error&&error.message?error.message:"network error");
    }finally{
      button.disabled=false;
      button.textContent="Проверить ещё раз ↗";
    }
  });
})();
</script>
</body>
</html>"""
        if docs_enabled:
            page = page.replace(
                "<!-- API_DOCS_LINK -->",
                '<a href="/docs">Документация API ↗</a>',
            )
        else:
            page = page.replace("<!-- API_DOCS_LINK -->", "")
        return HTMLResponse(content=page)

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
            raise HTTPException(
                status_code=503,
                detail="Signing is disabled until an encrypted issuer key is configured",
            )
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
            raise HTTPException(
                status_code=503,
                detail="Signing is disabled until an encrypted issuer key is configured",
            )
        _role_for_request(request, "revoker")
        try:
            manager.revoke(payload.status_list_index)
            metrics.operations.labels("revoke", "success").inc()
            return {"revoked": True, "status_list_index": payload.status_list_index}
        except StatusListError as exc:
            metrics.operations.labels("revoke", "failure").inc()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        @application.get("/demo/status-list")
    def demo_status_list(request: Request) -> dict[str, Any]:
        demo_manager: StatusListManager | None = request.app.state.demo_status_manager
        if not request.app.state.demo_enabled or demo_manager is None:
            raise HTTPException(status_code=503, detail="Browser demo is not configured")
        try:
            return demo_manager.create_credential()
        except StatusListError as exc:
            metrics.errors.labels("demo_status_list").inc()
            raise HTTPException(status_code=500, detail="Could not publish demo status list") from exc

    @application.post("/demo/issue")
    def demo_issue(request: Request) -> dict[str, Any]:
        demo_manager: StatusListManager | None = request.app.state.demo_status_manager
        demo_key: Ed25519PrivateKey | None = request.app.state.demo_issuer_key
        demo_name: str = request.app.state.demo_issuer_name
        if not request.app.state.demo_enabled or demo_manager is None or demo_key is None:
            raise HTTPException(status_code=503, detail="Browser demo is not configured")
        try:
            status_entry = demo_manager.allocate()
            credential = create_credential(
                demo_key,
                issuer_name=demo_name,
                achievement_name="Practical safety — browser demo",
                achievement_description=(
                    "Synthetic demonstration credential. Not a real qualification."
                ),
                credential_status=status_entry,
            )
            index = int(status_entry["statusListIndex"])
            request.app.state.demo_registry.register(index, credential["id"])
            metrics.operations.labels("demo_issue", "success").inc()
            return credential
        except (ValueError, StatusListError) as exc:
            metrics.operations.labels("demo_issue", "failure").inc()
            raise HTTPException(status_code=400, detail="Could not create demo credential") from exc

    @application.post("/demo/verify")
    def demo_verify(request: Request, payload: VerifyRequest) -> dict[str, Any]:
        demo_manager: StatusListManager | None = request.app.state.demo_status_manager
        if not request.app.state.demo_enabled or demo_manager is None:
            raise HTTPException(status_code=503, detail="Browser demo is not configured")
        status = payload.credential.get("credentialStatus")
        try:
            index = int(status["statusListIndex"]) if isinstance(status, dict) else -1
        except (KeyError, TypeError, ValueError):
            index = -1
        if index < 0 or not request.app.state.demo_registry.matches(
            index, payload.credential.get("id")
        ):
            raise HTTPException(
                status_code=403,
                detail="Credential was not issued by the public demo issuer",
            )
        try:
            result = verify_credential(
                payload.credential,
                status_list_credential=demo_manager.create_credential(),
            )
        except (ValueError, StatusListError) as exc:
            raise HTTPException(status_code=400, detail="Could not verify demo credential") from exc
        metrics.operations.labels(
            "demo_verify", "success" if result.get("valid") else "invalid"
        ).inc()
        return result

    @application.post("/demo/revoke")
    def demo_revoke(request: Request, payload: VerifyRequest) -> dict[str, Any]:
        demo_manager: StatusListManager | None = request.app.state.demo_status_manager
        if not request.app.state.demo_enabled or demo_manager is None:
            raise HTTPException(status_code=503, detail="Browser demo is not configured")
        status = payload.credential.get("credentialStatus")
        try:
            index = int(status["statusListIndex"]) if isinstance(status, dict) else -1
        except (KeyError, TypeError, ValueError):
            index = -1
        if index < 0 or not request.app.state.demo_registry.matches(
            index, payload.credential.get("id")
        ):
            raise HTTPException(
                status_code=403,
                detail="Credential was not issued by the public demo issuer",
            )
        try:
            demo_manager.revoke(index)
            metrics.operations.labels("demo_revoke", "success").inc()
            return {"revoked": True, "status_list_index": index}
        except StatusListError as exc:
            metrics.operations.labels("demo_revoke", "failure").inc()
            raise HTTPException(status_code=400, detail="Could not revoke demo credential") from exc

    @application.post("/admin/clients", status_code=201)
    def create_client(request: Request, payload: ClientCreateRequest) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
        try:
            return registry.register_client(payload.name, payload.roles, payload.scopes)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.get("/admin/clients")
    def list_clients(request: Request) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
        return {"clients": registry.list_clients()}

    @application.post("/admin/clients/{client_id}/tokens")
    def issue_client_token(
        request: Request, client_id: str, payload: ClientTokenRequest
    ) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
        try:
            return registry.issue_token(client_id, payload.expires_in, payload.scopes)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/clients/{client_id}/rotate")
    def rotate_client_token(
        request: Request, client_id: str, payload: ClientTokenRequest
    ) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
        try:
            return registry.rotate_token(client_id, payload.expires_in)
        except ClientRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.post("/admin/clients/{client_id}/revoke")
    def revoke_client(request: Request, client_id: str) -> dict[str, Any]:
        _role_for_request(request, "admin")
        registry: ClientRegistry | None = request.app.state.client_registry
        if registry is None:
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
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
            raise HTTPException(
                status_code=503, detail="Encrypted client registry is not configured"
            )
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
                content=impact_store.export_csv(),
                media_type="text/csv; charset=utf-8",
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
