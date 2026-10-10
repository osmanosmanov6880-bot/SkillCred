# Security policy

## Status

SkillCred is an experimental MVP. It has not received a professional security audit or formal Open Badges certification. Do not use it for high-stakes credentialing, legal identity proofing, regulated licensing or decisions that materially affect a person's rights until the gaps described here are reviewed and closed.

## Reporting a vulnerability

Do not publish exploit details or real learner data in a public issue.

For a private report, contact the repository maintainers through the private security reporting feature of the hosting platform, if enabled. If it is unavailable, use a maintainer contact published in the repository metadata. Include:

- affected version or commit;
- impact and conditions required to reproduce;
- a minimal proof of concept without personal data;
- whether the issue has been disclosed elsewhere.

Maintainers should acknowledge a report within 5 business days, triage severity, coordinate a fix and provide a reasoned disclosure timeline. These are target service levels for the project, not a guarantee during the pre-institutional pilot. Reporters should not access or modify data beyond what is necessary to demonstrate the issue.

## Security design

- Ed25519 signatures are provided by the `cryptography` library.
- Wallets use Scrypt and AES-256-GCM; private keys are not displayed by `info` or exported in plaintext.
- Verification makes no network calls and derives the public key from the credential's `did:key` verification method.
- A signature establishes integrity and possession of a key, not the real-world identity or competence of the issuer.
- The API stores the issuer key in `issuer-wallet.scw`, encrypted using Scrypt and AES-256-GCM. Configure `SKILLCRED_KEY_PASSPHRASE` or `SKILLCRED_KEY_PASSPHRASE_FILE`; the file path must refer to a protected regular file. If no passphrase is configured, persistent signing is disabled. `SKILLCRED_PRIVATE_KEY_B64` remains only as a legacy secret injection/migration path and should be avoided for new deployments. Production still needs reviewed secret management or hardware-backed keys; an environment variable is a deployment seam, not a complete key-custody solution.
- `/issue`, `/verify`, and `/revoke` use role-scoped bearer tokens: issuer, verifier, and revoker respectively; `admin` is a super-role. Configure distinct >=32-character ASCII tokens via `SKILLCRED_API_TOKENS` or a protected `SKILLCRED_API_TOKENS_FILE`. The legacy `SKILLCRED_API_TOKEN` is mapped to admin for migration only. Tokens must not be committed or logged. The local fixed-window rate limiter is per process, not a distributed security boundary.
- Recipient identifiers are optional; never add telemetry that transmits credential subjects without a separately reviewed purpose and informed basis.
- Status lists are public and signed, but an old signed list may be stale. A relying party needs a freshness policy.

## Known security gaps before internet exposure

1. Client JWTs are short-lived and checked against the encrypted local registry, but there is no full external identity provider, MFA, or delegated administrative workflow. Keep the bootstrap admin token as break-glass only.
2. The client registry is a single-writer encrypted file. Multiple replicas must not write it concurrently; a transactional shared store and concurrency tests are prerequisites for horizontally scaled issuance.
3. Redis-backed rate limiting is optional. In-memory fallback is per process and not a shared abuse-control boundary. Multi-replica deployments require Redis health monitoring and reverse-proxy/gateway controls.
4. Key rotation, hardware-backed key-management integration and compromised-key recovery are not implemented.
5. Local file locking is not evidence of safe distributed state. Use one writer/replica until a shared status-list backend has been tested.
6. Credential/status-list freshness policies and automated list rotation are not fully implemented.
7. Full official Open Badges schema and 1EdTech conformance suite have not run in this authoring environment.
8. Ruff, Docker/Compose, PyLD and external RFC 8785 test dependencies were not available for local execution; CI must be run in a network-enabled environment.
9. No third-party cryptography, privacy or application security audit has been completed.

## Incident response

1. Contain affected deployment and preserve minimal evidence.
2. Determine affected versions, credentials, key material and data categories.
3. Rotate or revoke compromised keys if the issuer can do so safely.
4. Notify affected operators and people where appropriate and legally required.
5. Publish a remediation advisory when disclosure no longer creates unreasonable risk.
6. Add regression tests and review whether governance or operational failures contributed.


## Role authorization and operational controls

- `issuer`: issue credentials, but not revoke unless separately granted another role.
- `revoker`: revoke allocated status indexes.
- `verifier`: submit online verification requests. Offline CLI verification does not require API tokens.
- `admin`: can perform protected API operations. Avoid routinely using this role.
- `/status-list`, `/issuer`, `/health`, and `/metrics` are public endpoints by design; inspect what operational information is appropriate for your deployment.
- The rate limiter is fixed-window, per process and IP/path. It emits 429 with `Retry-After` when exceeded; it is not a substitute for reverse-proxy limits.
- Use `THREAT_MODEL.md` and `pilot/deployment_checklist.md` before a pilot.


## SkillCred 0.2.0 controls

The API uses distinct role-specific bearer tokens (`issuer`, `revoker`, `verifier`, `admin`) configured through `SKILLCRED_API_TOKENS` or a protected `SKILLCRED_API_TOKENS_FILE`. A legacy `SKILLCRED_API_TOKEN` is admin-only for migration. Tokens must be distinct and contain at least 32 ASCII characters. The built-in rate limiter is fixed-window and per-process; it is not a replacement for ingress protection or a shared limiter in multi-replica deployments. Request bodies are capped at 1 MiB by default.

Persistent API signing keys are stored in the Scrypt + AES-256-GCM encrypted wallet. Configure `SKILLCRED_KEY_PASSPHRASE` or `SKILLCRED_KEY_PASSPHRASE_FILE` from a secret manager. A file-based passphrase must not be readable by group/others on POSIX. `/ready` returns 503 if persistent signing is unavailable; `/health` only indicates that the process responds.

The API limiter and token map are operational controls, not a complete identity provider. Use private networking/TLS, rotate tokens, monitor failed requests, and do not expose the service directly to an untrusted public network until independent review and a distributed abuse-control plan are complete.

The API rejects wallet passphrases shorter than 12 characters. This is only a minimum guardrail; use a unique high-entropy secret supplied through a manager or protected file and plan rotation/recovery.

## Client token lifecycle

Normal clients should use short-lived Ed25519-signed JWT access tokens, not share the bootstrap administrator secret. JWTs are verified with the locally pinned issuer public key and checked against the encrypted client registry on every protected request. The registry enforces expiry, audience, issuer, granted role/scope, client state, token `jti` revocation, and token-version rotation. The registry is encrypted using Scrypt + AES-256-GCM and its secret must be held by a secret manager.

The current client registry is a local-file single-writer implementation. Do not mount it read/write to multiple replicas and assume distributed transaction safety. Client registration and token issuance require an administrator principal; admin client grants are disabled unless `SKILLCRED_ALLOW_CLIENT_ADMIN=true` is explicitly configured.

## Rate limiting

The API supports optional Redis shared counters (`SKILLCRED_REDIS_URL`) plus bounded in-memory fallback. Fallback after Redis errors is documented as availability-first; it is not a distributed quota guarantee. Keep a rate-limit policy in the reverse proxy/WAF and alert when Redis fallback occurs. Do not trust forwarded client-IP headers unless the proxy is configured to overwrite them.

## Impact data

Impact collection is local and schema-constrained. It does not accept free text or direct personal identifiers; organization references are pseudonymous codes. Keep `impact.sqlite3` in the protected data directory, restrict admin export, encrypt backups and define a retention period with pilot participants. CSV exports can be re-identifying when combined with outside information and must be handled as restricted data.


## Issuer discovery and federation trust

`/.well-known/skillcred-issuer.json` is discovery metadata, not a signed claim of legal identity. The endpoint contains no learner records and SkillCred does not automatically fetch the URLs it advertises. Pin a remote DID only after independently checking the expected DID and service URL. Local pins are operator-controlled, not a global trust root.

## Bootstrap token files

`SKILLCRED_API_TOKEN_FILE` supports a single bootstrap admin token. On POSIX systems the file must be a regular file and not readable by group/others. Prefer a secret manager mount with restrictive ownership. The older `SKILLCRED_API_TOKEN` environment variable remains a migration path; rotate it after client JWTs are operational.

## 0.3.0 review boundary

`PENTEST_REPORT.md` is a source-based desk review using regression tests, not an independent penetration test. The official 1EdTech suite, PyLD JSON-LD processing and the complete RFC 8785 vector set were not run in the authoring environment. Do not expose the service publicly or use it for high-impact decisions until the relevant external tests and deployment review have passed.
