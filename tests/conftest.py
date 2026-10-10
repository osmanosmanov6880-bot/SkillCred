from __future__ import annotations

import pytest

from skillcred.keys import generate_keypair


@pytest.fixture(autouse=True)
def _secure_api_test_defaults(monkeypatch):
    """Every API test uses encrypted persisted keys unless it tests failure mode."""
    monkeypatch.setenv("SKILLCRED_KEY_PASSPHRASE", "test-only-passphrase-never-use-in-production")
    monkeypatch.delenv("SKILLCRED_KEY_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("SKILLCRED_PRIVATE_KEY_B64", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKENS", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKENS_FILE", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKEN", raising=False)
    monkeypatch.delenv("SKILLCRED_API_TOKEN_FILE", raising=False)


@pytest.fixture
def private_key():
    return generate_keypair()
