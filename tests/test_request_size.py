from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from skillcred.request_size import RequestSizeLimitMiddleware


def test_rejects_declared_oversized_body_without_reading_it() -> None:
    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=8)

    @app.post("/echo")
    def echo(payload: dict[str, object]) -> dict[str, object]:
        return payload

    response = TestClient(app).post(
        "/echo", content=b"{}", headers={"content-length": "999"}
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"


def test_accepts_body_at_limit() -> None:
    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=2)

    @app.post("/echo")
    def echo(payload: dict[str, object]) -> dict[str, object]:
        return payload

    response = TestClient(app).post("/echo", content=b"{}")
    assert response.status_code == 200
    assert response.json() == {}


def test_refuses_invalid_middleware_limit() -> None:
    app = FastAPI()
    with pytest.raises(ValueError, match="must be positive"):
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=0)
        TestClient(app).get("/")


def test_rejects_oversized_stream_without_content_length() -> None:
    from fastapi import Request

    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=8)

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    response = TestClient(app).post("/echo", content=iter([b"12345", b"67890"]))
    assert response.request.headers.get("content-length") is None
    assert response.status_code == 413
