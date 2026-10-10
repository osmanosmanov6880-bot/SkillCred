#!/usr/bin/env bash
set -euo pipefail

: "${SKILLCRED_1EDTECH_SUITE_DIR:?Set SKILLCRED_1EDTECH_SUITE_DIR to the official 1EdTech suite directory}"
: "${SKILLCRED_1EDTECH_COMMAND:?Set SKILLCRED_1EDTECH_COMMAND to the runner command documented by the configured suite version}"

suite_dir="$(cd "$SKILLCRED_1EDTECH_SUITE_DIR" && pwd)"
if [[ ! -d "$suite_dir" ]]; then
  echo "Suite directory not found: $suite_dir" >&2
  exit 2
fi
if [[ ! -f "$suite_dir/README.md" && ! -f "$suite_dir/README" && ! -f "$suite_dir/package.json" ]]; then
  echo "The configured directory does not look like a test-suite checkout; inspect its official instructions." >&2
  exit 2
fi

# Intentionally do not guess the official runner: 1EdTech's conformance programs
# can change between releases. The operator must set the command from that suite's docs.
printf 'Suite: %s\nRunner: %s\n' "$suite_dir" "$SKILLCRED_1EDTECH_COMMAND"
cd "$suite_dir"
# The command is intentionally supplied by the operator after reading official docs.
bash -lc "$SKILLCRED_1EDTECH_COMMAND"
