"""Endpoint-aware fixed-window rate limiter with Redis and in-memory fallback.

Set SKILLCRED_REDIS_URL to share counters between replicas. If Redis is missing
or fails, the middleware falls back to bounded process-local counters. That
fallback preserves service availability but is not a distributed security
boundary; production ingress should also enforce limits at the reverse proxy.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import defaultdict
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from skillcred.auth import authorized_roles, load_token_config
from skillcred.i18n import language_from_accept_header, translate

logger = logging.getLogger("skillcred.rate_limit")
_EXEMPT_PATHS = {"/health", "/ready", "/metrics"}
_DEFAULT_PATH_LIMITS = {
    "POST /issue": 12,
    "POST /revoke": 12,
    "POST /admin/clients": 10,
    "POST /admin/clients/{client_id}/tokens": 20,
    "POST /admin/clients/{client_id}/rotate": 10,
    "POST /verify": 90,
}
_DEFAULT_ROLE_LIMITS = {"issuer": 12, "revoker": 12, "verifier": 90, "admin": 60}


def _json_limit_map(env_name: str, defaults: dict[str, int]) -> dict[str, int]:
    raw = os.environ.get(env_name)
    if not raw:
        return dict(defaults)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError
        result: dict[str, int] = {}
        for key, value in parsed.items():
            if not isinstance(key, str) or not key or isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100_000:
                raise ValueError
            result[key] = value
        return result
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"{env_name} must be a JSON object of positive integer limits") from exc


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        limit: int | None = None,
        window_seconds: int | None = None,
        redis_client: Any | None = None,
    ):
        super().__init__(app)
        self.limit = max(1, limit if limit is not None else int(os.getenv("SKILLCRED_RATE_LIMIT", "120")))
        self.window_seconds = max(
            1,
            window_seconds if window_seconds is not None else int(os.getenv("SKILLCRED_RATE_WINDOW_SECONDS", "60")),
        )
        self.path_limits = _json_limit_map("SKILLCRED_RATE_LIMITS_JSON", _DEFAULT_PATH_LIMITS)
        self.role_limits = _json_limit_map("SKILLCRED_ROLE_RATE_LIMITS_JSON", _DEFAULT_ROLE_LIMITS)
        self._events: dict[tuple[str, int], int] = defaultdict(int)
        self._lock = threading.Lock()
        self.redis = redis_client
        self.redis_configured = bool(os.getenv("SKILLCRED_REDIS_URL")) or redis_client is not None
        self.redis_available = self.redis is not None
        self._fallback_reported = False
        if self.redis is None and os.getenv("SKILLCRED_REDIS_URL"):
            try:
                from redis.asyncio import Redis
                self.redis = Redis.from_url(os.environ["SKILLCRED_REDIS_URL"], decode_responses=True, socket_timeout=0.5)
                self.redis_available = True
            except ImportError:
                self.redis_available = False

    @staticmethod
    def _route_template(request: Request) -> str:
        route = request.scope.get("route")
        return str(getattr(route, "path", request.url.path))

    def _selected_limit(self, request: Request) -> int:
        method = request.method.upper()
        path = request.url.path
        selected = self.limit
        for configured, ceiling in self.path_limits.items():
            configured_method, _, template = configured.partition(" ")
            if configured_method != method:
                continue
            expected_parts = template.strip("/").split("/")
            actual_parts = path.strip("/").split("/")
            if len(expected_parts) != len(actual_parts):
                continue
            if all(expected.startswith("{") and expected.endswith("}") or expected == actual
                   for expected, actual in zip(expected_parts, actual_parts, strict=True)):
                selected = min(selected, ceiling)
        return selected

    def _partition(self, request: Request) -> tuple[str, str]:
        client_host = request.client.host if request.client else "unknown"
        authorization = request.headers.get("authorization", "")
        # Never persist bearer secrets in keys or logs. Hash only for a stable bucket.
        subject_hash = hashlib.sha256(authorization.encode("utf-8")).hexdigest()[:20] if authorization else "anonymous"
        return client_host, subject_hash

    async def _redis_increment(self, key: str) -> int:
        assert self.redis is not None
        # Use a Lua script where supported so the expiry cannot be lost between
        # INCR and EXPIRE if a connection drops. Minimal test doubles may expose
        # only INCR/EXPIRE; those use the conservative two-command fallback.
        evaluator = getattr(self.redis, "eval", None)
        if evaluator is not None:
            script = "local c=redis.call('INCR',KEYS[1]); if c == 1 then redis.call('EXPIRE',KEYS[1],ARGV[1]); end; return c"
            return int(await evaluator(script, 1, key, self.window_seconds))
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, self.window_seconds)
        return int(count)

    def _memory_increment(self, key: tuple[str, str, int]) -> int:
        with self._lock:
            old_window = key[2]
            for item in list(self._events):
                if item[2] < old_window - 1:
                    del self._events[item]
            self._events[key] += 1
            return self._events[key]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)
        now = int(time.time())
        bucket = now // self.window_seconds
        host, subject = self._partition(request)
        route = self._route_template(request)
        selected_limit = self._selected_limit(request)
        # The role policy is mapped to the verified static-token role when possible.
        # JWT client identity is still separately bucketed by token fingerprint and
        # route; role verification occurs in the endpoint, never from an untrusted header.
        try:
            token = request.headers.get("authorization")
            if token:
                config = load_token_config()
                roles = authorized_roles(token, config)
                registry = getattr(request.app.state, "client_registry", None)
                compact = token.split(" ", 1)[1] if token.lower().startswith("bearer ") else ""
                if registry is not None and compact.count(".") == 2:
                    roles.update(registry.verified_roles_for_rate_limit(compact))
                limits = [self.role_limits[r] for r in roles if r in self.role_limits]
                if limits:
                    selected_limit = min(selected_limit, min(limits))
        except Exception:
            # Malformed auth config is handled by the protected endpoint; rate
            # limiting continues with the conservative endpoint/global cap.
            pass
        key_tuple = (f"{host}:{subject}:{request.method}:{route}", bucket)
        backend = "memory"
        count = 0
        if self.redis is not None and self.redis_available:
            redis_key = f"skillcred:rl:{host}:{subject}:{request.method}:{route}:{bucket}"
            try:
                count = await self._redis_increment(redis_key)
                backend = "redis"
            except Exception as exc:
                self.redis_available = False
                if not self._fallback_reported:
                    logger.warning("Redis rate limiter unavailable; switching to process-local fallback (%s)", type(exc).__name__)
                    self._fallback_reported = True
                    metrics = getattr(request.app.state, "metrics", None)
                    if metrics is not None:
                        metrics.errors.labels("rate_limit_redis_fallback").inc()
                count = 0
        elif self.redis_configured and not self._fallback_reported:
            logger.warning("Redis rate limiter is configured but the optional redis package/client is unavailable; using process-local fallback")
            self._fallback_reported = True
            metrics = getattr(request.app.state, "metrics", None)
            if metrics is not None:
                metrics.errors.labels("rate_limit_redis_fallback").inc()
        if backend == "memory":
            count = self._memory_increment((key_tuple[0], subject, bucket))
        if count > selected_limit:
            reset = self.window_seconds - (now % self.window_seconds)
            return JSONResponse(
                status_code=429,
                content={"detail": translate("rate_limit", language_from_accept_header(request.headers.get("accept-language")))},
                headers={
                    "Retry-After": str(max(1, reset)),
                    "X-RateLimit-Limit": str(selected_limit),
                    "X-RateLimit-Backend": backend,
                },
            )
        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(selected_limit))
        response.headers.setdefault("X-RateLimit-Backend", backend)
        return response
