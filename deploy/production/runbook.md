# SkillCred production-oriented runbook (example, not a certification)

## Before deployment

1. Pin the SkillCred release and image by digest; review `SECURITY.md` and `PENTEST_REPORT.md`.
2. Provision TLS at Caddy/Nginx or an approved gateway. Do not expose the ASGI port directly to the public internet.
3. Put signing-key and client-registry passphrases and bootstrap admin credentials in Vault/Kubernetes Secrets. Use separate values; do not pass credentials on command lines or commit environment files.
4. Keep the data volume encrypted at rest and writable only by the service account. One writer per local client registry is required in this release.
5. Configure shared Redis rate limiting and also enforce proxy-level limits. Alert on limiter fallback.
6. Restrict `/metrics` and `/metrics/impact` to monitoring/admin networks. Protect JSON/CSV impact exports as restricted data.
7. Set `SKILLCRED_STATUS_LIST_URL` to the externally reachable HTTPS list endpoint and verify the publication path from a separate network.

## Startup/readiness

- `/health` reports process liveness; it is not proof of issuer readiness.
- `/ready` must return 200 before traffic is served. A 503 indicates persistent signing storage is not ready.
- Perform a test issuance, offline verification, status-list fetch, revocation, and revoked-credential verification using a pilot test credential.
- Verify that logs contain no authorization header, token, private key, passphrase, credential subject ID or impact record payload.

## Encrypted backup and recovery

1. Use `backup_encrypted.sh` with a managed `BACKUP_AGE_RECIPIENT`. Backups contain issuer wallet, encrypted client registry, status-list state, and impact measurements.
2. Store backup encryption identities separately from the backup storage and test restore at least quarterly.
3. Stop the API before restoring to the service data directory. Run `restore_encrypted.sh` into a clean restricted directory, verify permissions and file integrity, and then start a separate API process against that directory.
4. Confirm issuer DID remains stable, existing status-list bits are preserved, a known token revocation is still enforced, new issuance works and the restored service can be rolled back safely.
5. Record recovery time, data loss window and deviations. Do not re-enable public traffic if the restored key identity changes unexpectedly.

## Incident and maintenance

Rotate client tokens after suspected exposure, revoke the affected client, preserve minimal forensic records, and never store token strings in tickets. For signing-key compromise, suspend issuance and publish a new issuer key/identity through a governed migration; do not silently replace the key because DID identity changes. Apply upgrades first to a restored staging copy and repeat the offline verification suite.
