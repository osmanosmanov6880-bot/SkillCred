from __future__ import annotations

import re
from pathlib import Path

from skillcred.i18n import is_rtl, translate

ROOT = Path(__file__).parents[1]


def test_accessibility_document_covers_cli_and_api_documentation():
    text = (ROOT / "ACCESSIBILITY.md").read_text(encoding="utf-8").lower()
    assert "wcag" in text
    assert "keyboard" in text or "клавиат" in text
    assert "contrast" in text or "контраст" in text
    assert "cli" in text and "api" in text


def test_cli_messages_are_plain_text_without_terminal_escape_sequences():
    for locale in ("en", "ru", "de", "fr", "es", "zh", "ar"):
        message = translate("wallet_created", locale)
        assert not re.search(r"\x1b\[[0-9;]*m", message)
        assert "\n" not in message


def test_language_direction_is_explicit_for_arabic():
    assert is_rtl("ar")
    assert not is_rtl("de")
