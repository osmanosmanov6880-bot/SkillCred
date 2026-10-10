from __future__ import annotations

import pytest
from skillcred.i18n import (
    MESSAGES,
    SUPPORTED_LANGUAGES,
    is_rtl,
    language_from_accept_header,
    normalize_language,
    translate,
)


@pytest.mark.parametrize("language", ["ru", "en", "de", "fr", "es", "zh", "ar"])
def test_all_supported_languages_have_required_security_messages(language):
    for key in ("bearer_required", "bad_token", "role_denied", "rate_limit", "wallet_created"):
        assert MESSAGES[language][key]
    assert translate("wallet_created", language)


def test_locale_region_variants_and_quality_values():
    assert normalize_language("fr-CA") == "fr"
    assert normalize_language("zh_CN") == "zh"
    assert language_from_accept_header("de;q=0.3, ar;q=0.9, en;q=0.8") == "ar"
    assert language_from_accept_header("unsupported;q=0.9, en;q=0.5") == "en"


def test_rtl_is_enabled_for_arabic_only():
    assert is_rtl("ar") is True
    assert is_rtl("ar-EG") is True
    assert is_rtl("en") is False
    assert len(SUPPORTED_LANGUAGES) >= 7
