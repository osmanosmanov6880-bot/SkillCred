# SkillCred Y-deployment report

Date: 2026-10-10
Status: public HTTPS smoke test **PASS**; post-restart recovery check **PASS**, with raw HTTP outputs published.
Project status: experimental pilot; not 1EdTech-certified.

## Public service

- URL: https://skillcred-pilot-api.onrender.com
- Render service: `skillcred-pilot-api`
- Region and plan: Frankfurt, Starter
- Persistent disk: 1 GB, mounted at `/var/lib/skillcred`
- Health check: `/ready`
- Git repository: https://github.com/osmanosmanov6880-bot/SkillCred

## External HTTPS acceptance test

The operator ran the smoke script from a separate Windows/Git Bash terminal. All eight endpoint requests returned HTTP 200. Individual timings (seconds):

| Check | HTTP | Seconds |
|---|---:|---:|
| GET /health | 200 | 0.468966 |
| GET /ready | 200 | 0.444017 |
| GET /issuer | 200 | 0.352503 |
| POST /issue | 200 | 0.341286 |
| POST /verify before revoke | 200 | 1.378322 |
| POST /revoke | 200 | 0.436245 |
| POST /verify after revoke | 200 | 0.455052 |
| GET /metrics | 200 | 0.369572 |

Sum of the eight measured request times: 4.245963 seconds. Mean per request: 0.530745 seconds.

The test credential was synthetic and had status-list index `0`.

Before revocation:
```json
{
  "valid": true,
  "signature_valid": true,
  "status": "active",
  "issuer": "did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s",
  "credential_id": "urn:uuid:77917889-2183-4282-a907-6f105e1b957b",
  "errors": []
}
```

After revocation:
```json
{
  "valid": false,
  "signature_valid": true,
  "status": "revoked",
  "issuer": "did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s",
  "credential_id": "urn:uuid:77917889-2183-4282-a907-6f105e1b957b",
  "errors": ["Credential is revoked"]
}
```

## Render deployment and restart evidence

The first build succeeded, but the first container start failed because application startup tried to chmod the mounted disk. This was fixed in commit `c2d45bf03acd43e11f2ec1b4430abba7fef80efa` by adding a root entrypoint that prepares mounted-volume permissions before dropping privileges.

- Successful deploy after fix: `dep-db595fcs728c73c9j2r0`, status `live` at 2026-10-10 19:33:02 UTC.
- Recovery/redeploy: `dep-db59rs4s728c73cbt3c0`, status `live` at 2026-10-10 20:21:06 UTC.
- Render runtime logs confirmed Uvicorn startup and `GET /ready` → HTTP 200 after each successful deployment.
- Render service metadata confirmed a 1 GB persistent disk mounted at `/var/lib/skillcred`.

## Recovery verification

Before the recovery redeploy, a separate synthetic credential was issued with status-list index `1`; the external verifier returned HTTP 200 and `valid=true, status=active`. Its credential ID was `urn:uuid:83e1b31f-82ce-4492-8276-cb630415ca93`.

The operator ran the fixed recovery script after the Render restart, and the raw response files have now been published in `deployment-evidence/`. All five post-restart checks returned HTTP 200: `/health`, `/ready`, `/issuer`, verification of the active synthetic credential, and verification of the previously revoked credential. The issuer DID before and after restart matched (`did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s`). The active credential remained `valid=true`, `signature_valid=true`, `status=active`; the previously revoked credential remained `valid=false`, `signature_valid=true`, `status=revoked`, with error `Credential is revoked`. An earlier recovery-check attempt returned HTTP 401 for the verification request; the subsequent corrected rerun passed. The published files preserve the final successful response bodies and timings.

## Evidence files

- [External smoke summary](deployment-evidence/external-smoke-summary.tsv)
- [External transcript excerpt](deployment-evidence/external-smoke-transcript.md)
- [Render lifecycle log excerpt](deployment-evidence/render-lifecycle.md)
- [Recovery verification record](deployment-evidence/recovery-operator-report.md)
- [Raw recovery summary](deployment-evidence/recovery-after-restart-summary.tsv)
- [Active credential response after restart](deployment-evidence/recovery_active_after_restart.json)
- [Revoked credential response after restart](deployment-evidence/recovery_revoked_after_restart.json)

Secrets, API tokens and passphrases are intentionally excluded from the public repository.
