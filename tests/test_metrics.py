from __future__ import annotations

from fastapi.testclient import TestClient

from skillcred.api import create_app


def test_metrics_exposes_request_and_operation_counters(tmp_path, monkeypatch):
    token = "metrics-admin-" + "m" * 40
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    client = TestClient(create_app(tmp_path))
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/issue", json={"achievement_name": "Metrics skill"}, headers=headers)
    assert response.status_code == 200
    result = client.get("/metrics")
    assert result.status_code == 200
    body = result.text
    assert "skillcred_http_requests_total" in body
    assert 'skillcred_operations_total{operation="issue",outcome="success"} 1.0' in body
    assert "skillcred_http_request_duration_seconds" in body


def test_metrics_errors_count_http_failures(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_API_TOKEN", "metrics-auth-" + "e" * 40)
    client = TestClient(create_app(tmp_path))
    assert client.post("/verify", json={"credential": {}}).status_code == 401
    body = client.get("/metrics").text
    assert "skillcred_errors_total" in body


def test_unmatched_paths_do_not_create_high_cardinality_metric_labels(tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.get("/missing-path-one").status_code == 404
    assert client.get("/missing-path-two").status_code == 404
    metrics = client.get("/metrics").text
    assert 'route="/unmatched"' in metrics
    assert "/missing-path-one" not in metrics
    assert "/missing-path-two" not in metrics
