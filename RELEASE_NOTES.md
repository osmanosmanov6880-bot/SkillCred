# SkillCred 0.3.0 — Release Notes

**Status:** experimental pilot candidate; not 1EdTech-certified. Release date: 2026-10-10.

## Highlights

- Client lifecycle: client registration, Ed25519-signed short-lived JWTs, scopes, expiry, single-token and client revocation, and token rotation.
- Encrypted client registry at rest using Scrypt-derived AES-256-GCM; documented single-writer boundary.
- Optional Redis-backed shared rate limiting, per-role/endpoint limits and explicit in-memory fallback behavior.
- Impact metrics with consent controls, pseudonymous organization code, small-group suppression and administrator-only JSON/CSV export.
- Federation discovery through `/.well-known/skillcred-issuer.json` with explicit local DID pinning; discovery never implies trust and arbitrary URLs are not fetched automatically.
- Issuer credentials use a random per-credential `urn:uuid:` subject identifier when no real-world learner identifier is provided, matching the official Open Badges `AchievementSubject` identifier requirement without requiring a central learner account.
- Pilot scenarios for universities, employers, NGOs, public sector and international projects; bilingual consent and data-processing templates.
- Production deployment examples for Nginx/Caddy, Vault/Sealed Secrets, Prometheus/Grafana, systemd/Kubernetes, encrypted backup/restore and independent recovery.
- ru/en/de/fr/es/zh/ar messages, Arabic RTL metadata, OWASP API Security Top 10 desk review, governance amendments, contributor ladder and release validation.

## Verification summary

Latest full local source run: **168 passed, 3 skipped, 85.95% coverage** (gate: 85%), Python 3.13.5. Skips are due to missing `rfc8785`, missing official 1EdTech schema file and missing PyLD. Local pilot-schema tests pass; they are not official certification tests.

The local environment check reports `blocked` as expected because mandatory runtime conformance dependencies PyLD and `rfc8785` are unavailable. Ruff, Docker/Compose, the official 1EdTech suite and hosted GitHub Actions did not run in this environment. See `VALIDATION_REPORT.md`.

## Known limitations

- Not 1EdTech-certified and not proven interoperable with all Open Badges wallets.
- No independent external penetration test was performed; `PENTEST_REPORT.md` is a desk review.
- Client registry uses single-writer file semantics, not concurrent multi-replica writes.
- The in-memory rate-limit fallback is per process; production requires Redis or trusted ingress enforcement.
- Issuer discovery is not trust; the relying party must verify and pin the DID out of band.
- Status-list freshness/expiry, issuer-key compromise recovery and full official conformance remain open.
- Cryptographic validity does not establish legal issuer identity or assessment quality.

## Rollback

Back up the encrypted issuer wallet, status state, encrypted client registry, trusted issuer pins, impact database where retention policy permits, and deployment configuration. In an isolated recovery instance, verify issuer DID continuity, revocation state, client registry integrity and successful issuance before switching traffic. Never restore plaintext secrets into source control.
