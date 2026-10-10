# Recovery verification record

Date: 2026-10-10  
Service: https://skillcred-pilot-api.onrender.com

## Before restart

The recovery preparation script returned:

```text
recovery_issue                 HTTP=200 time=0.586574s
Recovery credential status-list index: 1
recovery_verify_before_restart HTTP=200 time=0.472579s
Before restart: {"valid": true, "signature_valid": true, "status": "active", "issuer": "did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s", "credential_id": "urn:uuid:83e1b31f-82ce-4492-8276-cb630415ca93", "errors": []}

PASS: active synthetic credential issued and verified before restart.
```

## Restart

Render redeployed commit `c2d45bf03acd43e11f2ec1b4430abba7fef80efa`. The deployment returned to `live`; Render logs show Uvicorn startup and `GET /ready` → HTTP 200. Service metadata confirmed the same 1 GB disk remained mounted at `/var/lib/skillcred`.

## Post-restart verifier

The operator reported that the recovery script completed successfully and its verification checks passed. The exact final terminal output was not pasted into the conversation, so this report labels the result as operator-reported rather than quoting response values that were not captured here. The script's local files should be published alongside this report for a full raw transcript when available.

No secrets are included.
