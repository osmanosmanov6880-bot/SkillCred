# SkillCred 0.3.0 — External Operator Runbook

This runbook is intended for an operator who did not write SkillCred.

## 1. Prepare

Requirements: Python 3.11+, pip, a supported OS, and reviewed project source. Docker is optional. Never copy a private production key into a developer workstation.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest --cov=skillcred --cov-report=term-missing
```

## 2. Configure bootstrap and issuer secrets

Use a distinct high-entropy bootstrap administrator token to administer local client records. For routine clients, prefer scoped short-lived JWTs issued by the encrypted client registry rather than permanent static role tokens. Static role tokens remain available as a controlled bootstrap/emergency mechanism and should be disabled or rotated after client migration.

Generate the bootstrap secret once and place it in a secret manager; never put it in source control or shell history. Configure the encrypted issuer-wallet passphrase and client-registry passphrase through separate secret files where practical:

```bash
export SKILLCRED_API_TOKEN_FILE=/run/secrets/skillcred-bootstrap-admin
export SKILLCRED_KEY_PASSPHRASE_FILE=/run/secrets/skillcred-key-passphrase
export SKILLCRED_CLIENT_STORE_PASSPHRASE_FILE=/run/secrets/skillcred-client-store-passphrase
export SKILLCRED_DATA_DIR="$PWD/skillcred-data"
export SKILLCRED_STATUS_LIST_URL="https://pilot.example.invalid/status-list"
```

`example.invalid` is reserved for documentation; replace it with the actual HTTPS URL before issuing publicly referenced credentials. The bootstrap token must be >=32 ASCII characters. A token sourced from a file is preferred; use a supported launcher/secret-manager injection mechanism and protect process inspection and logs. Routine clients should receive JWTs with minimum roles/scopes and short expiry.

## 3. Start privately

```bash
uvicorn skillcred.api:app --host 127.0.0.1 --port 8000
```

For a remote pilot, use a trusted reverse proxy with TLS and keep the application listener private. For multiple replicas, configure `SKILLCRED_REDIS_URL` and install the `redis` extra; if Redis fails, the app falls back to in-memory limits, so proxy-level limits remain mandatory.

## 4. Test role boundaries

Using a client that reads tokens from the organization's secret manager:
- issuer can POST `/issue`, but cannot POST `/revoke` unless also assigned revoker/admin;
- revoker can POST `/revoke`, but cannot POST `/issue` unless also assigned issuer/admin;
- verifier can POST `/verify`; it cannot issue or revoke;
- admin can perform all three operations;
- GET `/status-list`, `/issuer`, `/health`, and `/metrics` expose only public/operational information. Review metrics exposure before any internet-facing deployment.

Do not place token values in shell commands that are stored in shell history. Use a local client script reading from environment/secret manager and keep its output free of tokens.

## 5. Exercise issue → export → verify → revoke

1. Issue a synthetic badge using issuer role.
2. Save the returned JSON with mode `0600` where supported.
3. Transfer it to a separate host or clean container using a controlled channel.
4. Verify signature offline with the SkillCred CLI.
5. Fetch `/status-list`, then verify the badge with that status-list credential.
6. Revoke its `statusListIndex` using revoker role.
7. Fetch the updated `/status-list` and confirm final status `revoked`.

## 6. Recovery drill

1. Stop the process.
2. Back up the encrypted issuer wallet, `status-state.json`, and documented configuration separately. Never include secret files in the report.
3. Restore to a clean instance and use the same secrets.
4. Verify issuer DID is unchanged and status-list index does not rewind.
5. Issue, verify and revoke a new synthetic credential.
6. Record operator time and unresolved gaps in `metrics_form.md`.

## 7. End the pilot safely

Export aggregated metrics; remove test credentials and secret copies per retention policy; rotate credentials if exposure is suspected; preserve only incident evidence with a documented basis. Never publish raw credentials that identify participants.

### Kubernetes secrets

Create `skillcred-secrets` through your secret manager integration. Do not apply a checked-in placeholder secret. For bootstrap mode, mount a >=32-character ASCII admin token as a protected file and set `SKILLCRED_API_TOKEN_FILE`; or use a distinct role-map JSON only as a migration/emergency mechanism. `key-passphrase` and `client-store-passphrase` must be long, unique secrets. The checked-in Kubernetes template intentionally contains only non-secret configuration.


## 8. Client lifecycle and least privilege (0.3.0)

1. Use a separate bootstrap admin credential to register a client through `POST /admin/clients`.
2. Grant only the role needed; add optional scopes explicitly. Admin-client creation is disabled unless `SKILLCRED_ALLOW_CLIENT_ADMIN=true`.
3. Issue a short-lived token through `POST /admin/clients/{client_id}/tokens`; the bearer token is displayed once and must be stored by the client in its own secret manager.
4. Rotate via `POST /admin/clients/{client_id}/rotate`, revoke one token via `POST /admin/tokens/{jti}/revoke`, or revoke a client via `POST /admin/clients/{client_id}/revoke`.
5. Test that old tokens fail immediately after rotation, expired tokens fail, scopes cannot be escalated, and client revocation survives process restart.
6. Keep the encrypted client registry single-writer; it is not a multi-replica transactional store.

## 9. Pilot-specific playbooks and impact data

Choose the relevant playbook under `pilot/scenarios/` (university, employer, NGO, public sector, international project). Complete the consent notice in `pilot/consent_templates/` and have a privacy/legal review of the data processing agreement before collecting real-person data. Use only pseudonymous organization references in `POST /metrics/impact`; export CSV/JSON only for authorized administrators. Do not interpret results as causal proof without an appropriate evaluation design.

## 10. Production recovery

Use `deploy/production/backup_encrypted.sh` and `restore_encrypted.sh` with an `age` key held separately from the backup store. Follow `deploy/production/runbook.md`; confirm DID continuity and status-list state in a separate process before reopening traffic.


## 11. Explicit issuer federation

Read `/.well-known/skillcred-issuer.json` from the issuer's approved HTTPS origin. Do not automate arbitrary URL fetching from metadata. Compare the DID with an independently obtained fingerprint/record, then let an authorized admin pin that exact DID and status-list URL. A pin is a local trust decision and must be re-reviewed if the service URL or key changes.
