# SkillCred Y-deployment report

Date: 2026-10-10
Status: public HTTPS smoke test **PASS**; operator-reported recovery check **PASS**.
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

The operator subsequently reported that all post-restart verification checks passed. The exact raw output of that final recovery script was not included in the conversation transcript; keep the local output files in `deployment-evidence/` with the published release artifacts for a full audit trail. This limitation is disclosed rather than presenting an unobserved response body as if it were captured here.

## Evidence files

- [External smoke summary](deployment-evidence/external-smoke-summary.tsv)
- [External transcript excerpt](deployment-evidence/external-smoke-transcript.md)
- [Render lifecycle log excerpt](deployment-evidence/render-lifecycle.md)
- [Recovery verification record](deployment-evidence/recovery-operator-report.md)

Secrets, API tokens and passphrases are intentionally excluded from the public repository.
