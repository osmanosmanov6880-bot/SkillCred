"""A strict RFC 8785 JCS implementation for SkillCred's JSON profile.

If the `rfc8785` package is installed it is used directly. The fallback supports
JSON objects, arrays, strings, booleans, null and safe integers. It deliberately
rejects floats and integers outside the IEEE-754 safe range rather than emit a
canonical representation that might differ from ECMAScript/JCS.
"""

from __future__ import annotations

import json
from typing import Any

try:  # Use the standards package in a normal installation.
    import rfc8785  # type: ignore[import-not-found]
except ImportError:  # Offline development environments can use the strict fallback.
    rfc8785 = None


class CanonicalizationError(ValueError):
    """Input cannot be canonically serialized under the supported JCS profile."""


def _fallback(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise CanonicalizationError("Integer outside JCS safe range; install rfc8785")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("Floats require the rfc8785 package")
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise CanonicalizationError("Unpaired UTF-16 surrogate is not valid JCS input")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_fallback(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError("JSON object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(
            _fallback(key) + ":" + _fallback(value[key]) for key in keys
        ) + "}"
    raise CanonicalizationError(f"Unsupported JSON value: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 canonical UTF-8 bytes, or fail closed for unsupported JSON."""
    try:
        if rfc8785 is not None:
            result = rfc8785.dumps(value)
            return result if isinstance(result, bytes) else result.encode("utf-8")
        return _fallback(value).encode("utf-8")
    except CanonicalizationError:
        raise
    except Exception as exc:  # Normalize third-party library errors for callers.
        raise CanonicalizationError("Could not canonicalize JSON under RFC 8785") from exc
