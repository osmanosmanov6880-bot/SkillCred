from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from skillcred.rate_limit import RateLimitMiddleware


class BrokenRedis:
    async def incr(self, key):
        raise ConnectionError("redis unavailable")


class RequestWithParts:
    pass


def test_redis_failure_switches_to_memory_fallback():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limit=1, window_seconds=60, redis_client=BrokenRedis())

    @app.get("/resource")
    def resource():
        return {"ok": True}

    client = TestClient(app)
    first = client.get("/resource")
    assert first.status_code == 200
    assert first.headers["X-RateLimit-Backend"] == "memory"
    second = client.get("/resource")
    assert second.status_code == 429
    assert second.headers["X-RateLimit-Backend"] == "memory"
