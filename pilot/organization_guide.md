# SkillCred Pilot — Organization Guide

## Before you begin
1. Name a technical operator and an independent reviewer.
2. Use a dedicated test environment and synthetic participant data.
3. Read `SECURITY.md`, `SPEC.md`, and `VALIDATION_REPORT.md`.
4. Assign issuer, revoker, verifier, and admin secrets to separate people/systems; never put secrets in tickets, logs, shell history, or checked-in files.
5. Keep the API on a private network; do not expose a pilot host directly to the public internet.
6. Set an explicit data-retention/deletion period and contact for participant questions.

## Test workflow
1. Issue one synthetic credential through a user authorized as `issuer`.
2. Export the credential JSON to a different machine or clean container.
3. Verify it using an independent SkillCred installation or approved verifier, authorized as `verifier` only if using the API.
4. Publish the signed status list, revoke the test credential using a `revoker` account, then fetch the updated list.
5. Confirm signature integrity remains true while the overall result is `valid: false` and status is `revoked`.
6. Restore the service in a clean environment from documented backups, without help from the original developer.

## Data boundaries
- Do not use real learner identifiers for initial testing. When the caller omits one, SkillCred generates a random per-credential subject URN to satisfy the Open Badges 3.0 profile; this is not a central learner account.
- Do not upload credentials or logs to public ticket trackers.
- Share only aggregate metrics unless participants explicitly consent to more and the organization has lawful grounds.
- Report incidents through the private process in `SECURITY.md`.

## Stop conditions
Stop pilot activity for an exposed signing key, unexplained credential modification, inability to honor data deletion commitments, unremediated critical security issue, or evidence that a participant is being pressured to participate.
