#!/usr/bin/env python3
"""Explicitly download the current official Open Badges schema/context for validation.

Network access is required. This is opt-in so normal builds never silently depend on
remote JSON-LD contexts. The script records provenance and SHA-256 for review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ASSETS = {
    "official_ob3_achievementcredential_schema.json": "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
    "official_ob3_context.json": "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
}


def _validate_official_url(url: str) -> None:
    """Allow HTTPS URLs only on the official PURL host."""
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid official asset URL") from exc

    if (
        parsed.scheme != "https"
        or parsed.hostname != "purl.imsglobal.org"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise ValueError("Refusing a non-allowlisted official asset URL")


class _OfficialHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("schemas"))
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "retrieved_at": datetime.now(UTC).isoformat(),
        "warning": "Review official version changes before using these assets for certification.",
        "assets": {},
    }
    assets = manifest["assets"]
    opener = urllib.request.build_opener(_OfficialHTTPSRedirectHandler())
    try:
        for filename, url in ASSETS.items():
            _validate_official_url(url)
            # URL and every redirect are checked against the HTTPS host allowlist.
            request = urllib.request.Request(  # noqa: S310
                url,
                headers={"User-Agent": "SkillCred-schema-fetch/0.3"},
            )
            with opener.open(request, timeout=args.timeout) as response:
                data = response.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                raise ValueError(f"Official asset exceeds 10 MiB: {url}")
            parsed = json.loads(data)
            if not isinstance(parsed, dict):
                raise ValueError(f"Official asset is not a JSON object: {url}")
            target = args.output_dir / filename
            target.write_bytes(data)
            assets[filename] = {
                "url": url,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        print(
            f"Official schema fetch failed; existing files were not claimed to be current: {exc}",
            file=sys.stderr,
        )
        return 2
    (args.output_dir / "official_schema_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
