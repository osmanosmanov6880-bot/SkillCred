# Render lifecycle evidence

Service: `skillcred-pilot-api`  
Dashboard: https://dashboard.render.com/web/srv-db58u7o473hc73a9skog  
Public URL: https://skillcred-pilot-api.onrender.com  
Plan: Starter, Frankfurt  
Persistent disk: `dsk-db58u80473hc73a9sla0`, 1 GB, mount path `/var/lib/skillcred`.

## Initial failure and fix

The first Docker image build succeeded but the first process start failed with:

```text
PermissionError: [Errno 1] Operation not permitted: '/var/lib/skillcred'
```

Cause: application startup attempted to change permissions on the Render-mounted persistent disk after running as an unprivileged user.

Commit `c2d45bf03acd43e11f2ec1b4430abba7fef80efa` added `docker-entrypoint.sh`: it prepares the mounted directory's ownership/permissions as root and then starts Uvicorn under the dedicated `skillcred` user.

## Successful deploy and recovery redeploy

| Event | UTC timestamp | Observed result |
|---|---|---|
| Build after permission fix | 2026-10-10 19:32:46 | Build succeeded |
| First successful deployment | 2026-10-10 19:33:02 | Deploy `dep-db595fcs728c73c9j2r0` status `live` |
| Uvicorn started on port 8000 | 2026-10-10 19:32:56 | Startup completed |
| Render readiness request | 2026-10-10 19:33:00 | `GET /ready` HTTP 200 |
| Recovery redeploy shutdown | 2026-10-10 20:20:19 | Previous process shut down |
| New Uvicorn process started | 2026-10-10 20:20:59 | Startup completed |
| Render readiness request | 2026-10-10 20:21:04 | `GET /ready` HTTP 200 |
| Recovery deployment complete | 2026-10-10 20:21:06 | Deploy `dep-db59rs4s728c73cbt3c0` status `live` |

These are Render's recorded build/deploy/app-log times. External API status codes and latency are recorded separately in `external-smoke-summary.tsv`.
