# Render deployment for SkillCred 0.3.0

This Blueprint is configured for a **paid Starter web service plus a 1 GB persistent disk**. Render's Free web service filesystem is ephemeral and cannot preserve SkillCred's issuer wallet, encrypted client registry, revocation state, and impact records across restarts. Do not use a free instance for a real pilot unless all state has first been moved to separately tested durable services.

## Required facts before a first issuance

1. Connect a public or private Git repository that contains this Blueprint and Dockerfile to Render.
2. Create the service using `render.yaml`; confirm the resulting HTTPS `onrender.com` URL.
3. In the Render Environment page set secrets (never commit them):
   - `SKILLCRED_KEY_PASSPHRASE`: random secret, at least 12 characters; use a dedicated secret-manager value.
   - `SKILLCRED_CLIENT_STORE_PASSPHRASE`: a different random secret, at least 12 characters.
   - `SKILLCRED_API_TOKENS`: JSON object with distinct >=32-character ASCII tokens for `admin`, `issuer`, `verifier`, and `revoker`. Example *shape only*: `{"admin":"...","issuer":"...","verifier":"...","revoker":"..."}`. Generate values with a password manager or `python -c 'import secrets; print(secrets.token_urlsafe(48))'`; do not use the ellipses literally.
   - `SKILLCRED_STATUS_LIST_URL`: exact public URL `https://<service-host>/status-list` after Render assigns the hostname.
4. Save and wait for a deploy. The service must pass `GET /health` and `GET /ready` before pilot credentials are issued.
5. Confirm `/issuer` returns the expected DID; store it in the pilot record. Verify `/.well-known/skillcred-issuer.json` names that same DID.
6. From a separate network run the complete issue/verify/revoke procedure in `deploy/production/runbook.md`. Use only synthetic credentials for deployment acceptance.

## TLS and health

Render terminates TLS at its public load balancer and redirects HTTP to HTTPS. `healthCheckPath: /ready` checks persistent signing-key readiness; `/health` alone is only liveness. Keep the API port private to Render's ingress and do not create a public raw TCP service.

## State and cost

The selected Starter plan and persistent disk incur charges. Render's published compute price and disk price may change; verify the current dashboard total before creating the service. The 1 GB disk should be backed up and restoration-tested before real participants are onboarded. This Blueprint is a deployment definition; it does not create a Render account, grant hosting credentials, or deploy itself.
