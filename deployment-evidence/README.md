# SkillCred deployment evidence

This directory contains public, non-secret evidence from the SkillCred 0.3.0 Render pilot on 2026-10-10.

- `external-smoke-summary.tsv`: endpoint status and measured external HTTPS response times.
- `external-smoke-transcript.md`: the actual active-before-revoke and revoked-after-revoke verifier results pasted by the operator.
- `render-lifecycle.md`: Render service/disk configuration, deployment status and lifecycle log times.
- `recovery-operator-report.md`: record of the post-restart verification result reported by the operator.

Public service: https://skillcred-pilot-api.onrender.com

No API tokens, passphrases, private keys, or credential subject personal data are included. The tests used synthetic credentials.

Raw per-request JSON responses, HTTP headers, timing metadata, request payloads for synthetic credentials, and post-restart recovery results are now included in this directory. These files document the external HTTPS smoke test and the successful recovery verification. The test credentials are synthetic; do not add real subjects or secret values to this folder.
