# Iteration Y — deployment attempt report

**Checked:** 2026-10-10 (local runtime session)

## Result

**BLOCKED — no public deployment was created.** No public URL, live hosting logs, or public `curl` results exist in this session. It would be misleading to claim otherwise.

## Environment evidence

The runtime check found all of the following absent:

- Render CLI and `RENDER_API_KEY`.
- Railway CLI and `RAILWAY_TOKEN`.
- Fly CLI and `FLY_API_TOKEN`.
- Docker CLI.
- GitHub CLI/token (`gh`, `GITHUB_TOKEN`, `GH_TOKEN`).
- A Git repository remote for the provided SkillCred source tree.

The connected GitHub integration lists existing user repositories, but the available actions in this session do not expose repository creation. No unrelated repository was modified to host SkillCred.

## Why a free Render service is not a safe pilot target

Render's official documentation says Free web services do not preserve filesystem changes and cannot attach a persistent disk. SkillCred stores its encrypted issuer wallet, client registry, revocation state, and pilot measurements under `SKILLCRED_DATA_DIR`; losing that state after a restart would invalidate issuer continuity or lose revocations. Therefore the included Blueprint selects a Starter service plus a 1 GB persistent disk, which incurs charges. Sources: [Render free services](https://render.com/docs/free), [Render persistent disks](https://render.com/docs/disks), [Render health checks](https://render.com/docs/health-checks).

## Prepared deployment artifacts

- `render.yaml`: Render Blueprint, TLS termination through Render, persistent data disk, `/ready` health check, secrets prompted through the dashboard.
- `deploy/render/README.md`: exact configuration and acceptance steps.
- `scripts/deployment_preflight.sh`: checks host tools, Git remote, and hosting credential presence without printing secret values.

## Gate status

| Acceptance criterion | Result |
|---|---|
| Public HTTPS URL exists | **Not met** |
| `/health` and `/ready` checked via public URL | **Not met** |
| Public `/issue → /verify → /revoke` curl cycle | **Not met** |
| External logs/screenshots | **Not available** |
| Deployment configuration prepared | Met |
| Failure/blocker evidence recorded | Met |

The only honest status is **Y is blocked**. Per the user's gate, work must not advance to organization outreach or a real-user pilot without the live URL and full-cycle evidence. The concrete alternative is to connect a SkillCred Git repository to Render and provide hosting credentials in Render's secret interface, then repeat this report against the resulting URL. No secret values should be pasted into chat.
