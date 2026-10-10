"""Prometheus-compatible, low-cardinality metrics for one FastAPI app."""
from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest


@dataclass
class MetricsBundle:
    registry: CollectorRegistry
    requests: Counter
    request_latency: Histogram
    operations: Counter
    errors: Counter

    @classmethod
    def create(cls) -> "MetricsBundle":
        registry = CollectorRegistry(auto_describe=True)
        return cls(
            registry=registry,
            requests=Counter(
                "skillcred_http_requests_total",
                "HTTP requests handled by SkillCred",
                ["method", "route", "status"],
                registry=registry,
            ),
            request_latency=Histogram(
                "skillcred_http_request_duration_seconds",
                "HTTP request duration in seconds",
                ["method", "route"],
                registry=registry,
                buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            ),
            operations=Counter(
                "skillcred_operations_total",
                "Credential operations by operation and outcome",
                ["operation", "outcome"],
                registry=registry,
            ),
            errors=Counter(
                "skillcred_errors_total",
                "Handled SkillCred API errors",
                ["category"],
                registry=registry,
            ),
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)
