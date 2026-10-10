from __future__ import annotations

import pytest
from skillcred.jcs import CanonicalizationError, canonicalize, rfc8785


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
        (
            {"z": [True, None, False], "a": "line\nfeed"},
            b'{"a":"line\\nfeed","z":[true,null,false]}',
        ),
        (
            {"€": "Euro Sign", "\r": "Carriage Return", "😀": "Emoji"},
            '{"\\r":"Carriage Return","€":"Euro Sign","😀":"Emoji"}'.encode(),
        ),
        ([0, -1, 9007199254740991], b"[0,-1,9007199254740991]"),
    ],
)
def test_jcs_subset_vectors(value, expected):
    assert canonicalize(value) == expected


def test_jcs_sorts_keys_by_utf16_code_units():
    # U+10000 sorts before U+E000 in UTF-16 ordering, unlike code-point ordering.
    value = {"\ue000": 1, "\U00010000": 2}
    assert canonicalize(value) == '{"𐀀":2,"":1}'.encode()


def test_fallback_rejects_float_when_library_missing():
    if rfc8785 is not None:
        assert canonicalize({"n": 4.5}) == b'{"n":4.5}'
    else:
        with pytest.raises(CanonicalizationError):
            canonicalize({"n": 4.5})


def test_jcs_rejects_unsafe_integer():
    # I-JSON numbers must fit the IEEE-754 domain without unsafe integer rounding.
    with pytest.raises(CanonicalizationError):
        canonicalize({"n": 9007199254740992})


def test_unpaired_surrogate_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"bad": "\ud800"})


def test_rfc8785_section_3_2_2_official_example():
    """RFC 8785 §3.2.2 vector; run with the standards package in normal CI."""
    import json

    if rfc8785 is None:
        pytest.skip("full number serialization vector requires the rfc8785 dependency")
    input_json = r"""{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"""
    value = json.loads(input_json)
    expected = r"""{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}""".encode()
    assert canonicalize(value) == expected


def test_rfc8785_section_3_2_3_official_property_sort_vector():
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "😀": "Emoji: Grinning Face",
        "": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        r'{"\r":"Carriage Return","1":"One","'
        + "\u0080"
        + r'":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        r'"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    ).encode("utf-8")
    assert canonicalize(value) == expected
