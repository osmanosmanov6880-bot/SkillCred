from __future__ import annotations

import pytest

import skillcred.jcs as jcs
from skillcred.jcs import CanonicalizationError, canonicalize


def test_canonical_json_orders_keys_and_preserves_unicode() -> None:
    result = canonicalize({"z": 1, "ä": "é", "a": [True, None]})
    assert result.decode("utf-8") == '{"a":[true,null],"z":1,"ä":"é"}'


def test_fallback_rejects_float_and_unsafe_integer(monkeypatch) -> None:
    monkeypatch.setattr(jcs, "rfc8785", None)
    with pytest.raises(CanonicalizationError):
        canonicalize({"n": 1.5})
    with pytest.raises(CanonicalizationError):
        canonicalize({"n": 2**53})


def test_fallback_uses_utf16_key_sorting(monkeypatch) -> None:
    monkeypatch.setattr(jcs, "rfc8785", None)
    assert canonicalize({"\ue000": 1, "😀": 2}) == '{"😀":2,"\ue000":1}'.encode()


def test_fallback_rejects_invalid_unicode_and_non_json_types(monkeypatch) -> None:
    monkeypatch.setattr(jcs, "rfc8785", None)
    with pytest.raises(CanonicalizationError):
        canonicalize("\ud800")
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "not a string key"})
    with pytest.raises(CanonicalizationError):
        canonicalize(object())


def test_external_canonicalizer_errors_are_normalized(monkeypatch) -> None:
    class BrokenCanonicalizer:
        @staticmethod
        def dumps(_value):
            raise RuntimeError("failure")

    monkeypatch.setattr(jcs, "rfc8785", BrokenCanonicalizer)
    with pytest.raises(CanonicalizationError):
        canonicalize({"key": "value"})


def test_fallback_jcs_uses_utf16_key_ordering(monkeypatch) -> None:
    import skillcred.jcs as jcs

    monkeypatch.setattr(jcs, "rfc8785", None)
    # UTF-16 compares U+10000 as D800 DC00, before U+E000; Python code-point
    # sorting would put U+E000 first and therefore produce a non-JCS result.
    assert jcs.canonicalize({"\ue000": 1, "𐀀": 2}) == '{"𐀀":2,"\ue000":1}'.encode()
