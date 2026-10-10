# SkillCred Threat Model (STRIDE)

Version: 0.3.0. Status: engineering threat model, not an independent security audit.

## System and trust boundaries

Assets: issuer private key, encrypted wallet, API role tokens, credential integrity, status-list integrity/freshness, local status state, pilot participant privacy, governance records.

Trust boundaries: issuer operator ↔ API; API ↔ local filesystem; holder ↔ verifier; issuer ↔ public status-list consumer; container/proxy ↔ network; maintainers ↔ release artifacts; governing body ↔ participants.

Assumptions: host OS and secret manager are not already compromised; TLS is provided for network access beyond loopback; the operator chooses trusted issuers out of band. A `did:key` proves control of a key, not legal identity or competence.

## STRIDE register

Probability and impact are qualitative pre-mitigation ratings for a limited pilot: Low / Medium / High. They must be reassessed for each deployment.

| ID | STRIDE | Threat and asset | Probability | Impact | Mitigations and verification |
|---|---|---|---|---|---|
| T01 | Spoofing | Attacker obtains/guesses role token and issues fake badges | Medium | High | Separate high-entropy role tokens, constant-time comparisons, secret manager, rotation procedure; role-separation tests |
| T02 | Spoofing | Malicious issuer presents an unknown `did:key` as trusted | High | High | Trust policy and out-of-band issuer confirmation; explicitly display issuer DID/name; never equate signature validity with legal identity |
| T03 | Tampering | Credential fields changed after signing | Medium | High | JCS canonicalization and Ed25519 verification; mutation regression tests |
| T04 | Tampering | Status-list contents modified or signed by another key | Low | High | Verify status-list signature, issuer match, URL and purpose; tamper/status tests |
| T05 | Repudiation | Issuer disputes issuance or revocation | Medium | Medium | Preserve signed artifact and minimal audit evidence under documented retention; avoid logging credential subjects by default |
| T06 | Information disclosure | Private key or passphrase exposed in files, environment, backups or logs | Medium | Critical | Scrypt + AES-256-GCM wallet, owner-only files, secret manager, encrypted backups, log redaction; key-encryption tests |
| T07 | Information disclosure | Credential JSON or status-list correlation reveals learner information | Medium | High | Optional subject ID, minimize claims, synthetic data, consent and retention rules; privacy review |
| T08 | Denial of service | Request flood consumes CPU, memory or Scrypt resources | High if internet-facing | High | Keep private by default, fixed-window rate limiter, ingress limits, ASGI request-body cap (1 MiB default), edge request-size limits, monitoring; rate-limit and body-limit tests. Built-in limiter is process-local only |
| T09 | Elevation of privilege | Issuer token can revoke credentials or verifier token can issue | Medium | High | Role separation with admin super-role; negative authorization tests |
| T10 | Tampering | Concurrent status updates race or index is reused | Medium under multi-worker use | High | Filesystem lock and atomic state replacement; deploy one writer/replica only until concurrency and shared-storage semantics are externally tested |
| T11 | Spoofing/Tampering | Dependency, release or build artifact compromised | Medium | High | CI matrix, pinned artifact hashes in deployment records, dependency review, signed releases planned only after keys/process are established |
| T12 | Information disclosure | Metrics/logging exposes subjects or creates high-cardinality labels | Low–Medium | Medium | Metrics contain route/status/operation labels only; do not add credential ID, user ID, IP, or raw payload labels |
| T13 | Denial of service | Malformed status-list gzip causes decompression bomb | Medium | High | Bounded decompression and size checks; negative decoder tests; continue fuzz testing |
| T14 | Elevation of privilege | Admin/governance group captures technical decisions and token administration | Medium | High | Separate technical and participant governance, term limits, disclosed conflicts, independent appeal, exit/portability rights |
| T15 | Tampering | Stale but correctly signed status-list is accepted as current | High without freshness policy | High | Verifier must apply deployment-specific freshness policy; freshness/expiry is not fully implemented in this MVP, so no high-impact use |
| T16 | Repudiation | API operator claims a test or release passed without reproducible evidence | Medium | Medium | Record exact commit, dependency lock, command, test report and CI link; distinguish local test runs from official 1EdTech results |

## Additional controls in 0.2.0

- Role-separated tokens (`issuer`, `revoker`, `verifier`, `admin`) with constant-time token comparisons.
- Persistent issuer keys are created in the encrypted wallet (Scrypt + AES-256-GCM); no configured passphrase means signing readiness is false.
- `/ready` is distinct from `/health`; orchestrator readiness requires a persistent signing key.
- Request bodies default to a 1 MiB cap, including chunked requests without `Content-Length`.
- Prometheus labels are limited to route templates, HTTP methods/statuses, operation names, and outcomes.

## Release gates

Before an external pilot: no known unremediated critical vulnerability; role separation tests pass; issuer key is encrypted or held by a reviewed secret manager; service is private/TLS-protected as applicable; backup/recovery succeeds; participant consent and deletion process are ready.

Before production or high-impact use: external application and cryptographic review, official conformance review, multi-instance state design, freshness/rotation policy, formal operations runbook, and market-specific privacy/legal review are required.

## Residual risks

The default limiter is in-memory and per process; the API is not a full identity provider; credentials can be copied by holders; revocation lists have privacy/correlation trade-offs; the project is not certified; cryptographic proof cannot determine whether the issuer's assessment was fair or correct.


## Additional threats in 0.3.0

| ID | Threat | Impact | Controls | Residual boundary |
|---|---|---|---|---|
| T17 | JWT replay after client rotation | Unauthorized API operations until token expires if revocation state is unavailable | Token `jti`, client version, expiry and encrypted registry lookup on every protected request | Registry availability is required; distributed replica semantics are not supported by local file store |
| T18 | Scope escalation during token issuance | Client obtains privilege outside its grant | Requested scopes must be a subset of stored client grant; explicit empty scopes fail | Admin bootstrap is still a powerful role and must be carefully held |
| T19 | Redis unavailable or quota split across replicas | More requests than configured across replicas | Redis shared counters, fallback log/metric, proxy quotas | In-memory fallback is not distributed enforcement |
| T20 | Malicious issuer metadata / SSRF | Network access to internal systems or false trust | No automatic remote fetch; strict HTTPS/local URL syntax; explicit expected-DID pin | Operator must confirm DID and status URL out of band |
| T21 | Impact metric re-identification | Participant or organization inferred from exported summaries | No free text/direct personal fields; pseudonymous code; small-group suppression | External correlation is possible; handle export as restricted data |
| T22 | Incorrect release bundle | Stale or secret files published | Release validator checks versions, inventory and sensitive paths; checksums generated | GPG key identity must be trusted out of band; local signature alone is not publisher identity |
