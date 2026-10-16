# SkillCred

**SkillCred** is an open-source, local-first pilot tool for issuing, carrying, exporting and independently verifying digital confirmations of practical skills.

> **Объяснение простыми словами:** [что делает SkillCred, кому он нужен и как проект может зарабатывать](PRODUCT_OVERVIEW.md). Публичный пилотный API: <https://skillcred-pilot-api.onrender.com>.

- License: Apache-2.0.
- Runtime: Python 3.11+.
- Issuer keys: Ed25519; local wallet encrypted with Scrypt + AES-256-GCM.
- Credential proof: W3C Data Integrity `DataIntegrityProof` with `eddsa-jcs-2022` and RFC 8785 JSON Canonicalization Scheme (JCS).
- Revocation: issuer-managed W3C Bitstring Status List profile; status checks can be performed offline when the verifier has a signed current list.
- Local credential verification makes no network requests.

> **Pilot status, not certification.** The project uses a focused Open Badges 3.0-shaped credential profile. It is not yet 1EdTech-certified and does not claim full Open Badges 3.0 conformance. Current 1EdTech Open Badges materials show `eddsa-rdfc-2022` in credential examples and also use `eddsa-rdf-2022` in some shared proof-model material; the W3C Data Integrity EdDSA spec defines `eddsa-jcs-2022`, which SkillCred uses for deterministic offline signing. The reviewed 1EdTech material does not establish that this JCS suite is accepted by the current Open Badges certification profile. Do not infer interoperability: verify the exact target profile and official certification suite before claiming conformance. See [SPEC.md](SPEC.md).

## Download and verify the complete source

See [RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md) for how to obtain the latest source ZIP and verify its SHA-256 checksums.

## What this MVP does

- Generates an Ed25519 issuer key and stores it in a passphrase-encrypted local wallet.
- Issues a JSON-LD credential with `VerifiableCredential` and `OpenBadgeCredential` types.
- Signs the credential using W3C `eddsa-jcs-2022` proof construction.
- Verifies signatures offline from the self-certifying `did:key` verification method.
- Exports credentials as portable JSON and copies an encrypted wallet without exposing its plaintext key.
- Maintains a local issuer-controlled Bitstring Status List, with bounded decompression and state bound to the issuer key and status-list URL.
- Exposes an optional FastAPI endpoint for issuance, verification, status-list publication, revocation, liveness/readiness, and Prometheus metrics.
- Enforces role-scoped bearer tokens, a per-process rate limit, and a 1 MiB default request-body limit.

## Requirements

- Python 3.11 or later.
- Dependencies are listed in `pyproject.toml`. Normal installation requires package-index access once. The development container used to create this repository did not have PyPI network access, so the full dependency installation could not be verified here.

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
skillcred init --wallet issuer.wallet --issuer-name 'Example Skills Lab'
skillcred issue --wallet issuer.wallet --achievement 'Practical safety' --description 'Completed a practical skills assessment.' --out credential.json
skillcred verify credential.json
```

The CLI prompts for the wallet passphrase. For automation, `SKILLCRED_PASSWORD` can be supplied through an operating-system secret manager or CI secret store; do not put passphrases in scripts, command-line arguments or checked-in files.

`SKILLCRED_PASSWORD` is provided for automation and demo convenience; production systems should use an operating-system credential manager or hardware-backed key provider.

## Public landing page and live browser demo

The API root route `/` serves `skillcred/static/index.html`. OSGARD publishes the same self-contained page at `https://osgard.world/skillcred/`. The interface uses HTML, CSS and vanilla JavaScript, with no external fonts, analytics, or JavaScript CDN. The controls call the live SkillCred API; they do not sign a simulated credential in the browser.

The public demo issuer is isolated from the production issuer:
- `POST /demo/issue` issues a synthetic credential signed by a dedicated demo key.
- `POST /demo/verify` verifies its Ed25519 signature against the demo issuer and checks the demo's signed status list.
- `POST /demo/revoke` revokes only a credential recorded by the demo registry.
- `GET /demo/status-list` publishes the demo issuer's signed Bitstring Status List.

The demo signing key is stored in a separate encrypted wallet, using `SKILLCRED_KEY_PASSPHRASE`; it never uses the production issuer's private key. Set `DEMO_ISSUER_TOKEN` to a random server-only value of at least 32 ASCII characters to enable public demo routes. The browser never receives or sends that secret. The routes are intentionally public and limited to synthetic demo badges; per-route rate limits restrict issue and revoke to 5 requests/minute per client and verify to 30 requests/minute. A persistent SQLite registry ties revoke/verify actions to credentials issued through the demo and expires records after seven days.

The OSGARD frontend calls the API at `https://skillcred-pilot-api.onrender.com`. The API must be redeployed after backend changes, and its CORS policy permits `https://osgard.world` and `https://www.osgard.world`. The Render Blueprint generates `DEMO_ISSUER_TOKEN` and configures the public docs; sync the Blueprint or set that environment variable on the existing API service if it is not already configured. No separate website service is needed.

For the public API schema and interactive documentation, `SKILLCRED_ENABLE_API_DOCS=true` exposes `/docs`, `/redoc`, and `/openapi.json`. These describe the API and do not certify standards conformance.
## API

The local API listens on `127.0.0.1:8000` when started with `make run`.

```bash
# Set these through a protected secret manager; do not commit them.
export SKILLCRED_KEY_PASSPHRASE="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SKILLCRED_API_TOKENS="$(python -c 'import json,secrets; print(json.dumps({r:secrets.token_urlsafe(32) for r in ("issuer","revoker","verifier","admin")}))')"
make run
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/issue \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $(python -c 'import os,json; print(json.loads(os.environ["SKILLCRED_API_TOKENS"])["issuer"])')" \
  -d '{"achievement_name":"Practical safety","achievement_description":"Completed a skills assessment."}'
curl http://127.0.0.1:8000/status-list
```

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness and version |
| `GET` | `/ready` | Readiness; requires a persistent encrypted signing key |
| `GET` | `/metrics` | Prometheus-compatible operational counters and latency histogram |
| `GET` | `/issuer` | Public issuer identifier |
| `POST` | `/issue` | Issue signed credential; real-world learner identifier is optional; a random per-credential subject URN is generated |

When no real-world learner ID is supplied, SkillCred emits a random per-credential `urn:uuid:` subject identifier required by the published AchievementSubject schema. It is not derived from personal data or centrally stored, but is visible in the credential file.
| `POST` | `/verify` | Verify signature and optional status list (`verifier`/`admin` role) |
| `GET` | `/status-list` | Publish a signed current status-list credential |
| `POST` | `/revoke` | Revoke an allocated `status_list_index` |

**Authorization:** `/issue` requires role `issuer` or `admin`; `/revoke` requires `revoker` or `admin`; `/verify` requires `verifier` or `admin`. Use distinct >=32-character ASCII tokens in `SKILLCRED_API_TOKENS` (JSON role map) or `SKILLCRED_API_TOKENS_FILE`. `SKILLCRED_API_TOKEN` remains as a legacy admin-only migration path. A fixed-window process-local rate limiter and a 1 MiB default request-body limit are enabled. The rate limiter is not distributed; multi-replica deployments need an ingress/shared limiter.

**Key custody:** configure `SKILLCRED_KEY_PASSPHRASE` or `SKILLCRED_KEY_PASSPHRASE_FILE`. Persistent API keys are stored in `issuer-wallet.scw` encrypted with Scrypt + AES-256-GCM. If there is no configured passphrase, persistent signing is disabled. Keep the service loopback-only or on a private network and use a protected secret manager. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Environment diagnostics

```bash
python scripts/check_env.py
```

The command prints a JSON report and exits non-zero when required runtime dependencies are absent. Optional external conformance tools are reported separately. See [THREAT_MODEL.md](THREAT_MODEL.md) for trust boundaries and [ACCESSIBILITY.md](ACCESSIBILITY.md) for CLI accessibility commitments.

## End-to-end demo

```bash
make demo
```

The demo writes artifacts under `demo-output/`: a credential, a portable copy, an active signed status list and a revoked signed status list. It asserts that the credential verifies before revocation and fails the overall status check after revocation while its original issuer signature remains valid.

## Tests and quality checks

```bash
make test
make lint
```

Or run focused checks:

```bash
python -m pytest -q
python -m compileall -q skillcred tests examples
```

CI runs lint, tests, coverage and wheel/sdist builds. Use `python scripts/check_env.py` to inspect local tooling. The local pilot-profile schema in `schemas/openbadge-pilot.schema.json` is not the official 1EdTech schema. The official conformance suite is available through 1EdTech's certification workflow; official pass/certification is not claimed by this repository. `scripts/run_1edtech_suite.sh` accepts the exact runner command documented by the suite rather than guessing a runner that may change by release.

## Privacy model

- The recipient identifier is optional and omitted by default.
- Credential contents are stored wherever the holder chooses; SkillCred does not send them to a central repository.
- Local status state stores allocated numeric indices and revoked indices, not recipient identities.
- A verifier can verify a credential signature offline. To determine current revocation status, the verifier also needs a fresh signed status-list credential from the issuer or another distribution channel.
- A `did:key` identifies the public key, not a legal organization. Issuer-name claims still require an external trust policy.

## Limits before a wider pilot

1. Validate the credential against the official 1EdTech Open Badges 3.0 JSON Schema and full conformance test suite.
2. Test interoperability with at least two independent Open Badges wallets/verifiers.
3. Evaluate whether target ecosystems require `eddsa-rdfc-2022` instead of the MVP's `eddsa-jcs-2022` suite.
4. Complete external cryptographic and application security review.
5. Add shared/distributed rate limiting, key rotation, status-list rotation and operational backup/restore.
6. Review the status-list encoding against the exact target conformance suite and current W3C Recommendation before using it with real credentials.
7. Define a public issuer-trust and key-recovery policy; cryptographic proof alone does not establish issuer legitimacy.

## Standards and references

- [Open Badges Specification 3.0](https://standards.1edtech.org/open-badges/specifications/standards/v3p0)
- [Open Badges Conformance and Certification Guide](https://standards.1edtech.org/open-badges/specifications/standards/v3p0/cert)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [W3C Data Integrity EdDSA Cryptosuites](https://www.w3.org/TR/vc-di-eddsa/)
- [W3C Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)

See also [SPEC.md](SPEC.md), [SECURITY.md](SECURITY.md), [GOVERNANCE.md](GOVERNANCE.md) and [examples/pilot_checklist.md](examples/pilot_checklist.md).

## Project documents

- [Format and cryptographic limitations](SPEC.md)
- [Governance model](GOVERNANCE.md) and [community charter](CHARTER.md)
- [Ten-year roadmap](ROADMAP.md)
- [Contribution guide](CONTRIBUTING.md) and [security policy](SECURITY.md)
- [Metrics](METRICS.md), [red flags](RED_FLAGS.md), [critical review](CRITIC_REVIEW.md), [threat model](THREAT_MODEL.md), and [validation report](VALIDATION_REPORT.md)
- [External pilot runbook](pilot/runbook.md), [pilot checklist](pilot/deployment_checklist.md), and [compliance report template](compliance_report_template.md)

## Client lifecycle, roles and scopes (0.3.0 development)

In addition to the bootstrap administrator credential, SkillCred supports encrypted client registration and short-lived Ed25519-signed JWT access tokens. An administrator registers a client, grants a fixed role and permitted scopes, and issues an access token. Tokens include `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, and a client token version. The encrypted local registry allows individual token revocation, client revocation, and rotation that invalidates earlier tokens.

The encrypted registry is stored as `clients.enc` in the SkillCred data directory. Its passphrase comes from `SKILLCRED_CLIENT_STORE_PASSPHRASE`, `SKILLCRED_CLIENT_STORE_PASSPHRASE_FILE`, or the existing encrypted-key passphrase configuration. Protect that secret as carefully as the issuer wallet. The current registry uses a local encrypted file with single-process locking; it is not a multi-replica transactional database.

Example bootstrap registration (the bootstrap admin token must be supplied by a secret manager):

```bash
curl -sS -X POST http://127.0.0.1:8000/admin/clients \
  -H "Authorization: Bearer $SKILLCRED_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Pilot issuer","roles":["issuer"]}'
```

Issue a token for the returned `client_id` using `POST /admin/clients/{client_id}/tokens` with `{"expires_in":3600}`. The access token is returned once; store it in the client's secret manager. Rotate with `POST /admin/clients/{client_id}/rotate`, revoke one token with `POST /admin/tokens/{jti}/revoke`, or revoke a client with `POST /admin/clients/{client_id}/revoke`. The bootstrap administrator remains a break-glass path and must not be used by regular clients.

## Redis-backed rate limiting

Install the optional backend with `python -m pip install -e '.[redis]'` and set `SKILLCRED_REDIS_URL=redis://...`. Route defaults are conservative, and may be overridden via the JSON `SKILLCRED_RATE_LIMITS_JSON` map, e.g. `{"POST /issue":12,"POST /revoke":12,"POST /verify":90}`. `SKILLCRED_ROLE_RATE_LIMITS_JSON` configures role ceilings. Redis counters are shared by application instances; if Redis becomes unavailable or is not installed, counters fall back to process-local memory. That fallback is an availability mode, not a distributed security boundary: production must keep proxy-level rate limits too.

## Pilot impact measurements

`POST /metrics/impact` accepts a constrained record containing a pseudonymous organization code, scenario, verification time before/after, optional same-currency cost, satisfaction, portability outcome and explicit consent confirmation. It accepts no names, e-mail addresses or free-text fields. `GET /metrics/impact` and `?format=csv` require admin scope and export locally held records; summary groups smaller than three records are suppressed. Data remains in the local `impact.sqlite3` file. See `pilot/metrics_schema.json` and `tools/impact_report.py`.

## Conformance boundary

SkillCred's local JSON Schema is a documented pilot profile, not the official 1EdTech schema. `scripts/fetch_official_schemas.py` downloads official schema/context assets only when explicitly invoked and records URL, retrieval time and SHA-256. JSON-LD context processing and the official 1EdTech test suite must be run in a network-enabled controlled environment before claiming certification.


## Issuer discovery and federation pins (0.3.0)

`GET /.well-known/skillcred-issuer.json` publishes the local issuer DID, the supported pilot profile, proof suite, and status-list URL. Discovery is informational: it does not establish legal identity or imply trust. SkillCred never fetches a metadata-provided URL automatically.

An administrator may pin reviewed metadata locally via `POST /admin/federation/pins` with both the metadata and an `expected_issuer_id` independently confirmed out of band. Pins are local operator trust decisions in `trusted-issuers.json`; they are not a global trust registry or certification. A pin can be removed via `DELETE /admin/federation/pins/{issuer_id}`.

## Pilot impact and operational data

`POST /metrics/impact` requires the verifier role and `impact:write` scope. It stores only a constrained record, explicit consent flag, and pseudonymous organization code. Aggregates suppress groups smaller than three rows; that is a risk reduction, not a guarantee of anonymity. `GET /metrics/impact` JSON/CSV export requires admin.


## Public pilot deployment status

**Public endpoint:** Not assigned yet. The placeholder URL must be replaced only after a Render deployment is live and externally verified.

The release is not considered publicly deployed until the live HTTPS `/health` and `/ready` checks return HTTP 200 and an external synthetic credential test proves `issue → verify → revoke → verify` with the final verification reporting `valid=false` and `status=revoked`. Local test results are not public deployment evidence. See [`deploy/render/README.md`](deploy/render/README.md) and [`deploy/production/runbook.md`](deploy/production/runbook.md).

## Public pilot deployment (2026-10-10)

The experimental pilot API is deployed at **https://skillcred-pilot-api.onrender.com** on Render (Frankfurt, Starter plan). The service has a 1 GB persistent disk mounted at `/var/lib/skillcred`; Render's health-check path is `/ready`.

An external Windows/Git Bash smoke test completed over HTTPS. All eight requests returned HTTP 200: `/health`, `/ready`, `/issuer`, `POST /issue`, `POST /verify` before revocation, `POST /revoke`, `POST /verify` after revocation, and `/metrics`. The active credential verified with `valid=true, status=active`; after revocation it returned `valid=false, status=revoked`. The run's measured request times and transcript excerpt are in [deployment-evidence](deployment-evidence/README.md).

A subsequent Render redeploy of commit `c2d45bf03acd43e11f2ec1b4430abba7fef80efa` reached `Live`; Render logs show Uvicorn started and `GET /ready` returned 200. The operator reports the post-restart verification run completed successfully. This remains an **experimental pilot**, not a production certification or 1EdTech certification.
