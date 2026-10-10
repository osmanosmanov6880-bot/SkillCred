#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SKILLCRED_1EDTECH_SUITE_DIR:?Set SKILLCRED_1EDTECH_SUITE_DIR to the authorized official suite checkout}"
: "${SKILLCRED_1EDTECH_COMMAND:?Set SKILLCRED_1EDTECH_COMMAND to the documented runner command for the pinned suite}"
SUITE="$(cd "$SKILLCRED_1EDTECH_SUITE_DIR" && pwd)"
OUT="${SKILLCRED_COMPLIANCE_OUTPUT:-$ROOT/compliance-results/official-suite.log}"
mkdir -p "$(dirname "$OUT")"
if [[ ! -d "$SUITE" || ( ! -f "$SUITE/README.md" && ! -f "$SUITE/README" && ! -f "$SUITE/package.json" ) ]]; then
  echo "Configured suite directory does not look like a test-suite checkout" >&2
  exit 2
fi
{
  printf 'SkillCred official conformance run\n'
  printf 'suite_dir=%s\n' "$SUITE"
  printf 'suite_revision='; git -C "$SUITE" rev-parse HEAD 2>/dev/null || echo unknown
  printf 'python='; python --version 2>&1
  printf 'runner=%s\n' "$SKILLCRED_1EDTECH_COMMAND"
  echo '--- official runner output ---'
  cd "$SUITE"
  # Intentional shell command: trusted operator must take this exact command from
  # the documentation for the pinned authorized suite. Never accept it from a PR.
  bash -lc "$SKILLCRED_1EDTECH_COMMAND"
} 2>&1 | tee "$OUT"
