from __future__ import annotations

from urllib.request import Request

import pytest
from scripts.fetch_official_schemas import (
    _OfficialHTTPSRedirectHandler,
    _validate_official_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        "https://example.com/context.json",
        "https://purl.imsglobal.org.evil.example/context.json",
        "https://user@purl.imsglobal.org/context.json",
        "https://purl.imsglobal.org:444/context.json",
    ],
)
def test_rejects_non_allowlisted_official_asset_urls(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_official_url(url)


def test_accepts_allowlisted_official_https_url() -> None:
    _validate_official_url("https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json")


def test_rejects_redirect_to_non_allowlisted_host() -> None:
    handler = _OfficialHTTPSRedirectHandler()
    request = Request("https://purl.imsglobal.org/old-context.json")

    with pytest.raises(ValueError, match="allowlisted"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://example.com/redirect-target.json",
        )


def test_allows_redirect_to_allowlisted_host() -> None:
    handler = _OfficialHTTPSRedirectHandler()
    request = Request("https://purl.imsglobal.org/old-context.json")

    redirect = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://purl.imsglobal.org/new-context.json",
    )

    assert redirect is not None
    assert redirect.full_url == "https://purl.imsglobal.org/new-context.json"
