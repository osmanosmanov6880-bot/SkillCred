# SkillCred 0.3.0 — internal adversarial review

Review status: engineering self-review. This is not an independent security audit or official conformance result.

## Findings and patches applied

| # | Finding | Risk | Applied mitigation | Regression evidence / remaining boundary |
|---:|---|---|---|---|
| 1 | Status-state could be copied under a different issuer key or list URL | Indices could be interpreted under a different issuer | State is bound to issuer DID and canonical status-list URL; startup rejects mismatch | `test_status_state_is_bound_to_key_and_url` |
| 2 | Superficial URL parsing could accept credentialed or malformed status URLs | Confusing status authority or unexpected URL semantics | Parsed HTTPS URLs; loopback-only HTTP; credentials, fragments and invalid ports are rejected | `tests/test_statuslist.py`; DNS/IP trust still belongs to operator |
| 3 | Credential exports could be world-readable | Learner evidence disclosure | Atomic JSON writes default to owner-only file permissions on POSIX | CLI file-permission test; Windows ACLs are OS-specific |
| 4 | Issuer field could conflict with verification-method key | A signature could be misattributed | Verifier compares issuer DID and verification method DID | Wrong-issuer regression test |
| 5 | Gzip status-list data could expand excessively | Memory exhaustion | Bounded decoding and explicit input/decompressed-size limits | Malformed status-list tests; fuzzing not performed |
| 6 | Bit ordering or encoding could diverge from status-list expectations | Independent verifiers could report different status | Minimum 131072 bits, left-most-bit-first addressing, `u` base64url multibase prefix, no padding | Bit round-trip and boundary tests; official suite not run |
| 7 | A credential with a status entry might be treated as valid without a usable signed list | Revoked/unknown status could be overlooked | Overall validity requires a verifiable status list when status is present | Active/revoked and unsigned-list tests |
| 8 | Issuance/revocation endpoints could be reached without auth | Unauthorized credentials or revocations | Fail-closed bearer authorization with 401/403/503 behavior and constant-time secret comparison | API authorization tests |
| 9 | One role could perform another role's operation | Privilege escalation | Separate `issuer`, `revoker`, `verifier`, and `admin` roles | `tests/test_auth_roles.py` |
| 10 | API signing key could persist as base64 plaintext | Issuer key disclosure in backups/filesystem | Default persistent key is stored in Scrypt + AES-256-GCM wallet; no passphrase means persistent signing is disabled | Encryption/migration tests; production secret manager was not tested |
| 11 | Reusing the same bearer for every role expands blast radius | A single leaked secret enables multiple actions | Role map expects distinct >=32 ASCII-character tokens; legacy single token is admin-only compatibility | Auth tests; token rotation remains operator-managed |
| 12 | In-process rate limiting does not coordinate multiple workers | A client can exceed intended service-wide rate | Fixed-window limiter returns 429 and Retry-After; docs require shared ingress limiter for multi-replica use | Rate-limit tests; distributed limiter not implemented |
| 13 | Oversized or chunked request bodies could consume memory | Denial of service during JSON parsing | ASGI body-size middleware, 1 MiB default, rejects declared and streamed oversize bodies | `tests/test_request_size.py`; edge proxy limits still recommended |
| 14 | Dynamic URL labels in metrics could cause cardinality exhaustion | Memory/metrics storage growth and accidental path disclosure | Labels use route templates; unmatched routes collapse to `/unmatched` | `tests/test_metrics.py`; no subject/token labels |
| 15 | Import-time ASGI app might look ready while using an ephemeral key | Orchestrator could route issuance to a non-persistent instance | `/health` is liveness; `/ready` returns 503 without persistent signing key; mutating/status publication routes fail closed | API readiness tests; deployment probes updated |
| 16 | Key migration could silently replace issuer identity | Previously issued signatures/status lists become ambiguous | Migration compares encrypted-wallet identity and refuses mismatch before removing the legacy file | Legacy key migration tests |
| 17 | Old or stale but validly signed status snapshot could be accepted | Revoked credential may appear active against stale data | Documentation explicitly requires current list; freshness/expiry enforcement remains a release gate | Not suitable for high-impact decisions until freshness policy is implemented |
| 18 | Runtime dependency absence might silently be mistaken for standard compliance | Non-standard fallback may be mistaken for full JCS / JSON-LD processing | Environment checker reports missing PyLD/rfc8785; fallback rejects floats and unsafe integers; conformance report explicitly blocked | `scripts/check_env.py`; two tests skipped in this environment |
| 19 | Credential proof can be valid while issuer identity/assessment is fraudulent | Relying party over-trusts the signature | Documentation separates key control, legal identity and assessment quality; external issuer trust policy required | Process policy; cannot be inferred cryptographically |
| 20 | Community/governance capture | Sponsor or maintainer concentrates rule-making authority | Charter, term limits, transparency, independent appeal, exit rights and concentration thresholds are documented | Governance is a proposed policy, not a legally constituted body |

## Release blockers / not proven here

- Ruff was not installed in the authoring environment and could not be fetched from the package index.
- Docker/Compose was not available, so no image or deployment manifest was executed locally.
- PyLD and external `rfc8785` were absent; their tests are skipped locally.
- Official 1EdTech conformance suite was not run; the local JSON Schema is only a project pilot profile.
- No third-party cryptography, application-security, privacy or legal review was performed.
- Shared/distributed status-state locking, key rotation/recovery and status-list freshness/expiry remain limitations.

## Acceptance boundary

The current tests establish the documented local pilot behavior only. They do not establish certification, issuer legal identity, assessment quality, currentness of a status snapshot, or production-grade security. A controlled pilot must use private networking, independent secrets, synthetic-first tests, recovery exercises and explicit participant consent.
