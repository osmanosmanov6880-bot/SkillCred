from __future__ import annotations

import asyncio

from fastapi import FastAPI
from skillcred.rate_limit import RateLimitMiddleware


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expiries = {}

    async def incr(self, key):
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key, seconds):
        self.expiries[key] = seconds
        return True


def test_redis_counter_is_shared_across_two_middleware_instances():
    shared = FakeRedis()
    first = RateLimitMiddleware(FastAPI(), limit=2, window_seconds=60, redis_client=shared)
    second = RateLimitMiddleware(FastAPI(), limit=2, window_seconds=60, redis_client=shared)
    assert asyncio.run(first._redis_increment("shared-key")) == 1
    assert asyncio.run(second._redis_increment("shared-key")) == 2
    assert asyncio.run(first._redis_increment("shared-key")) == 3
    assert shared.expiries["shared-key"] == 60


def test_endpoint_limit_configuration_is_validated(monkeypatch):
    monkeypatch.setenv("SKILLCRED_RATE_LIMITS_JSON", '{"POST /issue": 2, "POST /revoke": 1}')
    middleware = RateLimitMiddleware(FastAPI())
    assert middleware.path_limits["POST /issue"] == 2
    monkeypatch.setenv("SKILLCRED_RATE_LIMITS_JSON", '{"POST /issue": -1}')
    try:
        RateLimitMiddleware(FastAPI())
        raise AssertionError("invalid limits must fail startup")
    except RuntimeError:
        pass
