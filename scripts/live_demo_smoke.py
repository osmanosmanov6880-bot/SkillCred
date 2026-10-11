from __future__ import annotations

import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = "https://skillcred-pilot-api.onrender.com"
ORIGIN = "https://osgard.world"


def call(path: str, *, method: str = "GET", body: dict | None = None, headers: dict | None = None):
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(BASE_URL + path, data=data, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            payload = response.read()
            content_type = response.headers.get("content-type", "")
            parsed = json.loads(payload) if "json" in content_type else payload.decode("utf-8", "replace")
            return response.status, dict(response.headers.items()), parsed
    except HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = payload.decode("utf-8", "replace")
        return exc.code, dict(exc.headers.items()), parsed
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Network request failed for {path}: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    status, _, health = call("/health")
    require(status == 200 and health.get("ok") is True, f"/health failed: HTTP {status} {health}")
    print(f"PASS /health: service={health.get('service')} version={health.get('version')}")

    status, _, ready = call("/ready")
    require(status == 200 and ready.get("ready") is True, f"/ready failed: HTTP {status} {ready}")
    require(health.get("demo_ready") is True, (
        "Public demo backend is not deployed/enabled yet. "
        "Latest local tests pass, but the live API does not report demo_ready=true."
    ))
    print("PASS /ready: persistent signing key available")
    print("PASS /health: isolated demo issuer reports ready")

    status, cors_headers, _ = call(
        "/demo/issue",
        method="OPTIONS",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    allowed_origin = cors_headers.get("access-control-allow-origin")
    require(status == 200 and allowed_origin == ORIGIN, (
        f"CORS preflight rejected: HTTP {status}, "
        f"access-control-allow-origin={allowed_origin!r}"
    ))
    print("PASS CORS: osgard.world may call the API")

    status, _, issuer = call("/issuer")
    require(status == 200 and isinstance(issuer.get("id"), str), f"/issuer failed: HTTP {status} {issuer}")
    print("PASS /issuer: public issuer metadata available")

    status, _, credential = call("/demo/issue", method="POST", body={})
    require(status == 200 and isinstance(credential.get("proof"), dict), (
        f"/demo/issue failed: HTTP {status} {credential}"
    ))
    demo_issuer = credential.get("issuer", {})
    require(isinstance(demo_issuer, dict) and demo_issuer.get("id") != issuer.get("id"), (
        "Demo credential did not use a separate issuer key"
    ))
    require(
        credential.get("proof", {}).get("cryptosuite") == "eddsa-jcs-2022",
        "Demo credential is missing the expected Ed25519/JCS proof suite",
    )
    print("PASS /demo/issue: synthetic credential signed by the separate demo issuer")

    status, _, active = call("/demo/verify", method="POST", body={"credential": credential})
    require(
        status == 200 and active.get("signature_valid") is True
        and active.get("valid") is True and active.get("status") == "active",
        f"Active credential verification failed: HTTP {status} {active}",
    )
    print("PASS /demo/verify: signature valid, status active")

    status, _, revoked = call("/demo/revoke", method="POST", body={"credential": credential})
    require(
        status == 200 and revoked.get("revoked") is True,
        f"/demo/revoke failed: HTTP {status} {revoked}",
    )
    status, _, checked = call("/demo/verify", method="POST", body={"credential": credential})
    require(
        status == 200 and checked.get("signature_valid") is True
        and checked.get("valid") is False and checked.get("status") == "revoked",
        f"Revoked status verification failed: HTTP {status} {checked}",
    )
    print("PASS revoke round trip: signature remains intact; status is revoked")
    print("LIVE DEMO: all production checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"LIVE DEMO FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
