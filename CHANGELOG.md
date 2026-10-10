# Changelog

## 0.3.0 — 2026-10-10

- Added encrypted client registry, Ed25519 JWT lifecycle, scopes, expiry, rotation and revocation.
- Added Redis-backed distributed rate limiting with in-memory fallback and per-role/endpoint configuration.
- Added impact metrics, CSV/JSON export and low-cardinality Prometheus metrics.
- Added issuer metadata discovery with explicit DID pinning and no automatic remote fetch.
- Added production deployment examples, independent recovery checks, pilot scenario packs, consent/data-processing templates, threat model and OWASP desk review.
- Expanded message localization to German, French, Spanish, Chinese and Arabic (RTL metadata).
- Tightened credential shape: issue a random per-credential subject URN when the caller supplies no real-world learner identifier, in line with the published AchievementSubject schema description.
- Added release-bundle generation, release validation and GPG-signed checksum workflow.
- Validation: 168 passed, 3 skipped, 85.95% coverage on Python 3.13.5. Official schema/PyLD/RFC 8785 external dependency and 1EdTech conformance remain unverified in this environment.

## 0.2.0

- Added client and API auth primitives, Redis-compatible rate limiting, impact metrics, localization, deployment examples and release validator.

## 0.1.0

- Initial local-first pilot profile: Ed25519 credential issuance, local encrypted wallet, CLI, FastAPI API, signed Bitstring Status List revocation, tests and governance documentation.
