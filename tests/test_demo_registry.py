from __future__ import annotations

import sqlite3

from skillcred.demo_registry import DemoCredentialRegistry


def test_demo_credential_registry_persists_and_matches(tmp_path) -> None:
    path = tmp_path / "demo.sqlite3"
    registry = DemoCredentialRegistry(path)
    registry.register(17, "urn:uuid:demo-credential")

    reopened = DemoCredentialRegistry(path)
    assert reopened.matches(17, "urn:uuid:demo-credential") is True
    assert reopened.matches(17, "urn:uuid:someone-else") is False
    assert reopened.matches(18, "urn:uuid:demo-credential") is False


def test_demo_registry_prunes_expired_entries(tmp_path, monkeypatch) -> None:
    import skillcred.demo_registry as module

    clock = [1_800_000_000]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    registry = DemoCredentialRegistry(tmp_path / "demo.sqlite3", ttl_seconds=120)
    registry.register(3, "urn:uuid:short-lived")
    assert registry.matches(3, "urn:uuid:short-lived") is True

    clock[0] += 121
    assert registry.matches(3, "urn:uuid:short-lived") is False
    registry.register(4, "urn:uuid:new-entry")
    with sqlite3.connect(tmp_path / "demo.sqlite3") as connection:
        expired_count = connection.execute(
            "SELECT count(*) FROM demo_credentials WHERE status_list_index = 3"
        ).fetchone()[0]
    assert expired_count == 0


def test_demo_registry_bounds_record_count(tmp_path, monkeypatch) -> None:
    import skillcred.demo_registry as module

    clock = [1_800_000_000]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    registry = DemoCredentialRegistry(tmp_path / "demo.sqlite3", max_records=100)
    for index in range(105):
        clock[0] += 1
        registry.register(index, f"urn:uuid:demo-{index}")

    with sqlite3.connect(tmp_path / "demo.sqlite3") as connection:
        count = connection.execute("SELECT count(*) FROM demo_credentials").fetchone()[0]
    assert count == 100
    assert registry.matches(104, "urn:uuid:demo-104") is True
