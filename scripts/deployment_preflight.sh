#!/usr/bin/env bash
set -euo pipefail

# Print presence only; never display credential contents.
missing=0
for binary in git docker curl; do
  if command -v "$binary" >/dev/null 2>&1; then
    printf 'PASS tool:%s=%s\n' "$binary" "$(command -v "$binary")"
  else
    printf 'BLOCKED tool:%s=missing\n' "$binary"
    missing=1
  fi
done

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  remote_count="$(git remote -v | wc -l | tr -d ' ')"
  if [ "$remote_count" -gt 0 ]; then printf 'PASS git_remote_count=%s\n' "$remote_count"; else printf 'BLOCKED git_remote=none\n'; missing=1; fi
else
  printf 'BLOCKED git_repository=none\n'
  missing=1
fi

for name in RENDER_API_KEY RAILWAY_TOKEN FLY_API_TOKEN; do
  if [ -n "${!name:-}" ]; then printf 'PASS credential:%s=present\n' "$name"; else printf 'BLOCKED credential:%s=absent\n' "$name"; missing=1; fi
done

if [ -f render.yaml ] && [ -f Dockerfile ]; then printf 'PASS deployment_files=present\n'; else printf 'BLOCKED deployment_files=missing\n'; missing=1; fi

if [ "$missing" -eq 0 ]; then
  printf 'PREFLIGHT=PASS\n'
else
  printf 'PREFLIGHT=BLOCKED; no deploy attempt was made because a public deployment cannot be authenticated or built safely in this environment.\n'
fi
exit "$missing"
