from __future__ import annotations

import json

from fastapi.testclient import TestClient

from skillcred.api import create_app
from skillcred.impact import ImpactRecordRequest, ImpactStore


def _admin(monkeypatch):
    token = "impact-admin-" + "K" * 48
    monkeypatch.setenv("SKILLCRED_API_TOKEN", token)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    return token


def _record(code: str, *, seconds: float = 100, current: float = 60):
    return {
        "organization_ref": code,
        "scenario": "university",
        "baseline_seconds": seconds,
        "current_seconds": current,
        "baseline_cost": 4.0,
        "current_cost": 2.5,
        "currency": "EUR",
        "satisfaction": 4,
        "portability_passed": True,
        "consent_confirmed": True,
    }


def test_impact_metrics_redact_small_groups_and_export(tmp_path):
    store = ImpactStore(tmp_path / "impact.sqlite3")
    store.add(ImpactRecordRequest.model_validate(_record("pilot-a")))
    assert store.summary()["groups"] == []  # Small groups are not summarized.
    store.add(ImpactRecordRequest.model_validate(_record("pilot-b")))
    store.add(ImpactRecordRequest.model_validate(_record("pilot-c")))
    summary = store.summary()
    assert summary["records"] == 3
    assert summary["groups"][0]["mean_verification_time_reduction_percent"] == 40.0
    assert summary["groups"][0]["portability_success_rate"] == 1.0
    assert "organization_ref" in store.export_csv()
    assert json.loads(store.export_json())["summary"]["records"] == 3


def test_impact_api_requires_scoped_verifier_and_admin_export(tmp_path, monkeypatch):
    admin = _admin(monkeypatch)
    client = TestClient(create_app(tmp_path))
    admin_header = {"Authorization": f"Bearer {admin}"}
    registered = client.post(
        "/admin/clients", headers=admin_header,
        json={"name": "Impact reporter", "roles": ["verifier"], "scopes": ["impact:write"]},
    )
    assert registered.status_code == 201, registered.text
    client_id = registered.json()["client_id"]
    token = client.post(
        f"/admin/clients/{client_id}/tokens", headers=admin_header,
        json={"expires_in": 600, "scopes": ["impact:write"]},
    ).json()["access_token"]
    response = client.post(
        "/metrics/impact", headers={"Authorization": f"Bearer {token}"}, json=_record("uni-001")
    )
    assert response.status_code == 201, response.text
    assert client.get("/metrics/impact").status_code == 401
    export = client.get("/metrics/impact", headers=admin_header)
    assert export.status_code == 200
    assert export.json()["export"]["records"][0]["organization_ref"] == "uni-001"
    csv_response = client.get("/metrics/impact?format=csv", headers=admin_header)
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]


def test_impact_rejects_missing_consent_and_personal_identifiers():
    bad_consent = _record("org-001")
    bad_consent["consent_confirmed"] = False
    try:
        ImpactRecordRequest.model_validate(bad_consent)
        assert False, "consent must be required"
    except ValueError:
        pass
    bad_id = _record("person@example.org")
    try:
        ImpactRecordRequest.model_validate(bad_id)
        assert False, "personal identifier must be rejected"
    except ValueError:
        pass
