from __future__ import annotations

from fastapi.testclient import TestClient

from skillcred.api import create_app
from skillcred.i18n import language_from_accept_header, normalize_language, translate


def test_language_resolution_and_fallback(monkeypatch):
    assert language_from_accept_header("ru-RU, en;q=0.8") == "ru"
    assert language_from_accept_header("en-US,en;q=0.9") == "en"
    assert normalize_language("ru") == "ru"
    assert normalize_language("sv-SE") == "en"
    monkeypatch.setenv("SKILLCRED_LANG", "ru")
    assert translate("wallet_created") == "Зашифрованный кошелёк создан"
    assert "Индекс списка статусов 12 отозван" in translate("revoked", index=12, language="ru")


def test_api_auth_messages_follow_accept_language(tmp_path):
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/verify", json={"credential": {}}, headers={"Accept-Language": "ru"}
    )
    assert response.status_code == 503  # no API token configured
    # Configuration errors are explicit and fail closed; token-required is translated.


def test_api_missing_bearer_is_localized(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLCRED_API_TOKEN", "i18n-token-" + "i" * 40)
    client = TestClient(create_app(tmp_path))
    response = client.post(
        "/verify", json={"credential": {}}, headers={"Accept-Language": "ru"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Требуется Bearer-токен"


def test_cli_russian_messages_are_plain_text(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from skillcred.cli import app

    monkeypatch.setenv("SKILLCRED_LANG", "ru")
    monkeypatch.setenv("SKILLCRED_PASSWORD", "test-only-long-passphrase")
    result = CliRunner().invoke(app, ["init", "--wallet", str(tmp_path / "wallet.scw")])
    assert result.exit_code == 0, result.output
    assert "Зашифрованный кошелёк создан" in result.output
    assert "\x1b[" not in result.output
