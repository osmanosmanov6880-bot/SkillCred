# SkillCred Pilot — Metrics Collection Form

Use one row per test run. Use synthetic IDs only; do not record learner names or credential subject identifiers.

| Field | Value |
|---|---|
| Organization pseudonym | |
| Run ID (random, non-identifying) | |
| Date/time (UTC, rounded to day where possible) | |
| Operator role (issuer/revoker/verifier) | |
| Credential shape validation | pass / fail / blocked |
| Signature verification | pass / fail / blocked |
| Status check before revoke | active / unexpected |
| Status check after revoke | revoked / unexpected |
| Issuance duration (ms) | |
| Verification duration (ms) | |
| Time spent with prior process (seconds/minutes) | |
| Time spent with SkillCred (seconds/minutes) | |
| Transfer to independent installation | pass / fail |
| Independent deployment/recovery | pass / fail |
| Defect ID (no personal data) | |
| Participant feedback summary (de-identified) | |

Do not collect IP addresses, precise location, full HTTP bodies, raw access tokens, or unnecessary participant-level event histories for the pilot metric set.
