# External HTTPS verifier transcript excerpt

Captured from the operator's successful run of `skillcred-public-smoke.sh` against https://skillcred-pilot-api.onrender.com.

```text
health             HTTP=200 time=0.468966s
ready              HTTP=200 time=0.444017s
issuer             HTTP=200 time=0.352503s
issue              HTTP=200 time=0.341286s
Credential status-list index: 0
verify_active      HTTP=200 time=1.378322s
Before revoke: {"valid": true, "signature_valid": true, "status": "active", "issuer": "did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s", "credential_id": "urn:uuid:77917889-2183-4282-a907-6f105e1b957b", "errors": []}
revoke             HTTP=200 time=0.436245s
verify_revoked     HTTP=200 time=0.455052s
After revoke: {"valid": false, "signature_valid": true, "status": "revoked", "issuer": "did:key:z6MktmPmK6AoaieCguVRMorrL2b16gEJgJqreTaJRWBWR37s", "credential_id": "urn:uuid:77917889-2183-4282-a907-6f105e1b957b", "errors": ["Credential is revoked"]}
metrics            HTTP=200 time=0.369572s

PASS: external HTTPS issue -> verify(active) -> revoke -> verify(revoked) completed.
```

The credential subject was synthetic. No API tokens or passphrases are recorded in this transcript excerpt.
