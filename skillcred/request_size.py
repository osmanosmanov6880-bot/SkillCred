"""ASGI request-size limit to bound JSON parsing and memory consumption."""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from typing import Any

ASGIApp = Callable[
    [dict[str, Any], Callable[..., Awaitable[dict[str, Any]]], Callable[..., Awaitable[None]]],
    Awaitable[None],
]


class RequestSizeLimitMiddleware:
    """Reject oversized request bodies before handing them to the framework.

    Requests with Content-Length are rejected before the body is read. Streaming
    requests are buffered only up to ``max_bytes + one received chunk`` so a
    missing Content-Length header cannot bypass the limit.
    """

    def __init__(self, app: ASGIApp, max_bytes: int | None = None) -> None:
        self.app = app
        configured = (
            max_bytes
            if max_bytes is not None
            else int(os.getenv("SKILLCRED_MAX_REQUEST_BYTES", str(1024 * 1024)))
        )
        if configured < 1:
            raise ValueError("max request size must be positive")
        self.max_bytes = configured

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length)
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length")
                return
            if content_length < 0:
                await self._reject(send, 400, "Invalid Content-Length")
                return
            if content_length > self.max_bytes:
                await self._reject(send, 413, "Request body too large")
                return

        body_parts: list[bytes] = []
        total = 0
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await self._reject(send, 413, "Request body too large")
                return
            body_parts.append(chunk)
            more_body = bool(message.get("more_body", False))

        body = b"".join(body_parts)
        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send: Callable[..., Awaitable[None]], status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})
