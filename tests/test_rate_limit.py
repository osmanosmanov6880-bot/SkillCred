from __future__ import annotations

from fastapi.testclient import TestClient
from skillcred.api import create_app


def test_rate_limit_returns_429_and_retry_after(tmp_path, monkeypatch):
    client = TestClient(create_app(tmp_path, rate_limit=2, rate_window_seconds=60))
    assert client.get("/issuer").status_code == 200
    assert client.get("/issuer").status_code == 200
    response = client.get("/issuer")
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_health_and_metrics_are_exempt_from_rate_limit(tmp_path):
    client = TestClient(create_app(tmp_path, rate_limit=1, rate_window_seconds=60))
    for _ in range(4):
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.get("/metrics").status_code == 200


def test_path_specific_limit_matches_dynamic_client_routes(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv(
        "SKILLCRED_RATE_LIMITS_JSON", json.dumps({"GET /admin/clients/{client_id}": 1})
    )
    app = create_app(tmp_path, rate_limit=100, rate_window_seconds=60)
    # The selected route matcher is tested directly because this API doesn't expose
    # a GET detail endpoint; no HTTP surface is added solely for a rate-limit test.
    from starlette.requests import Request

    middleware = next(m for m in app.user_middleware if m.cls.__name__ == "RateLimitMiddleware")
    del middleware  # Middleware factory configuration is exercised below with a probe app.
    from fastapi import FastAPI
    from skillcred.rate_limit import RateLimitMiddleware

    probe = FastAPI()
    limiter = RateLimitMiddleware(probe, limit=100)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/admin/clients/abc",
        "headers": [],
        "client": ("127.0.0.1", 1),
        "scheme": "http",
        "server": ("test", 80),
        "query_string": b"",
        "root_path": "",
        "http_version": "1.1",
    }
    request = Request(scope)
    assert limiter._selected_limit(request) == 1



def test_public_demo_routes_have_narrow_limits(monkeypatch):
    monkeypatch.delenv("SKILLCRED_RATE_LIMITS_JSON", raising=False)
    from fastapi import FastAPI
    from starlette.requests import Request
    from skillcred.rate_limit import RateLimitMiddleware

    limiter = RateLimitMiddleware(FastAPI(), limit=100, window_seconds=60)

    def request_for(path: str) -> Request:
        return Request({
            "type": "http", "method": "POST", "path": path, "headers": [],
            "client": ("127.0.0.1", 1234), "scheme": "https", "server": ("test", 443),
            "query_string": b"", "root_path": "", "http_version": "1.1",
        })

    assert limiter._selected_limit(request_for("/demo/issue")) == 5
    assert limiter._selected_limit(request_for("/demo/revoke")) == 5
    assert limiter._selected_limit(request_for("/demo/verify")) == 30
