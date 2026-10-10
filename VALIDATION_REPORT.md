# SkillCred 0.3.0 — validation report

Date: 2026-10-10. This report separates checks actually performed from checks blocked by missing external tooling. Status: **experimental pilot candidate; not 1EdTech-certified**.

## Environment

- Runtime: Python 3.13.5 on Linux.
- Present and exercised: `cryptography`, FastAPI, Pydantic v2, pytest, pytest-cov, httpx, `jsonschema`, PyYAML, `prometheus-client`, Typer, Uvicorn, setuptools.
- Missing: PyLD, external `rfc8785` package, Ruff, Docker/Compose, official 1EdTech conformance suite checkout.
- Package-index/network access was unavailable for installing missing packages and downloading official schema/context files.

## Checks that passed locally

- `python -m pytest --cov=skillcred --cov-report=term --cov-report=json:.coverage-final.json -q`: **168 passed, 3 skipped**.
- Branch-aware total coverage: **85.95%**, above the configured **85%** gate.
- Skips are exactly: (1) RFC 8785 full-number vector requiring the absent `rfc8785` package; (2) official 1EdTech schema test because the official schema could not be obtained into `schemas/`; (3) PyLD availability/processing test because PyLD is absent.
- `python -m compileall -q skillcred tests examples scripts tools`: passed.
- `bash -n` over shell scripts in `scripts/`, `tools/`, `deploy/`, and `1edtech/`: passed.
- TOML, YAML, JSON and local JSON Schema syntax/validation checks passed.
- Local pilot schema tests now enforce that `credentialSubject` has `id` or `identifier`, matching the official 1EdTech AchievementSubject schema's documented requirement. When caller omits a real-world learner identifier, SkillCred generates a fresh random `urn:uuid:` subject identifier per credential. It is not derived from personal data and is not stored centrally, but it remains visible to recipients of that credential.
- JWT client lifecycle: Ed25519-signed short-lived tokens, scopes, expiration, rotation, client/token revocation and encrypted registry behavior have tests.
- Authorization role separation, request-size cap, rate-limit behavior/fallback, metrics, localization, API and federation pinning have tests.
- `deploy/verify_independent.sh` was exercised against local API instances for issue → verify → revoke and recovery continuity. This is a local exercise, not proof of production deployment security.
- Release validator tests verify version consistency, required source files, ZIP/sdist/wheel integrity, metadata, likely secrets in packaged material, and parity between source ZIP and Markdown dump.
- Setuptools produced the wheel and source distribution. The wheel was installed into an isolated target directory; package version and API/metrics imports were smoke-tested.
- The source bundle contains project sources and docs but excludes local keys, wallet files, tokens, revocation state, demo output, caches and build outputs.
- `scripts/check_env.py` was run and wrote `/mnt/data/SkillCred-0.3.0-env-check.json`. It correctly reports `blocked` because PyLD and `rfc8785` are missing; Ruff, Docker and official suite are also unavailable. This is not a passing environment check.

## Blocked or not run

- **Official 1EdTech conformance/certification:** not run. The official suite and authorized runner were unavailable. The release is not described as certified.
- **Official Open Badges JSON Schema:** the current official schema URL is documented in `SPEC.md`, but the file could not be downloaded here. Local tests use `schemas/openbadge-pilot.schema.json`, explicitly an internal pilot schema, not a replacement for the official schema.
- **JSON-LD expansion/processing:** PyLD is absent; remote contexts are not dereferenced at runtime. Tests that need PyLD are skipped.
- **Full RFC 8785 number serialization:** external `rfc8785` is missing. The fallback supports a deliberately restricted JSON subset and rejects floats and unsafe integers. It is not a complete JCS implementation; production issuance must install declared runtime dependencies and exercise the official vector.
- **Ruff:** not run because executable unavailable and package-index access prevented installation.
- **Docker/Compose and production proxy deployment:** not run because Docker is not installed. Configuration syntax was reviewed; it is not evidence of a live container deployment.
- **GitHub Actions:** workflow files are configured but hosted CI/release jobs have not run in this environment.
- **Python matrix:** executed only on Python 3.13.5; Python 3.11 and 3.12 require CI confirmation.
- **External security audit / penetration test:** not performed. `PENTEST_REPORT.md` is a desk review against OWASP categories, not an independent penetration test.

## Important security and interoperability limits

- Client registry persistence is a single-writer encrypted file, not safe for concurrent multi-replica updates.
- Redis-backed rate limiting is optional. The in-memory fallback is per process and cannot enforce a global quota across replicas.
- Role-scoped short-lived JWTs are supported, but the API does not constitute a full organizational identity provider; bootstrap/admin credential custody remains an operator responsibility.
- Federation discovery never fetches arbitrary remote metadata automatically. Discovery is not trust: operators must verify issuer DID out of band and pin it explicitly.
- Revocation status requires a current signed list snapshot. Stale status lists, key compromise recovery, status-list freshness/expiration and full status-list suite interoperability remain gaps.
- API tokens and issuer keys must be provisioned through an actual secret manager or protected secret file. Do not expose the service publicly before production hardening and review.
- Credential proof validity does not prove legal issuer identity, the truth of assessment claims, or acceptance by a relying party.

## Reproduce core checks

```bash
python scripts/check_env.py
python -m pytest --cov=skillcred --cov-report=term --cov-report=json:.coverage-final.json -q
python -m compileall -q skillcred tests examples scripts tools
find scripts tools deploy 1edtech -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
python scripts/create_release_bundle.py --root . --output-dir /tmp/skillcred-release
python scripts/validate_release.py --root . --artifact-dir /path/to/dist --source-zip /tmp/skillcred-release/SkillCred-0.3.0.zip --source-dump /tmp/skillcred-release/SkillCred-0.3.0-source.md
```

## Standards reference check

- Open Badges 3.0 official specification: https://standards.1edtech.org/open-badges/specifications/standards/v3p0
- Official AchievementCredential JSON Schema: https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json
- Official Open Badges context: https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json
- W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- W3C EdDSA Cryptosuites: https://www.w3.org/TR/vc-di-eddsa/
- W3C Bitstring Status List 1.0: https://www.w3.org/TR/vc-bitstring-status-list/
- RFC 8785: https://www.rfc-editor.org/rfc/rfc8785

**Release decision:** suitable only for a limited, supervised external pilot with synthetic or low-risk credentials, private-network exposure, protected secrets and a documented rollback. Public production use and official conformance are not established by these local checks.
