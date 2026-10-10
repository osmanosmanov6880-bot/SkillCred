#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SKILLCRED_BASE_URL:-http://127.0.0.1:8000}"
LIVE_DATA_DIR="${SKILLCRED_DATA_DIR:?Set SKILLCRED_DATA_DIR to the live service data directory}"
if [[ -z "${SKILLCRED_KEY_PASSPHRASE:-}" && -z "${SKILLCRED_KEY_PASSPHRASE_FILE:-}" ]]; then
  echo "Set SKILLCRED_KEY_PASSPHRASE or SKILLCRED_KEY_PASSPHRASE_FILE via a secret manager." >&2
  exit 2
fi
: "${SKILLCRED_ISSUER_TOKEN:?Set issuer role token from secret manager}"
: "${SKILLCRED_VERIFIER_TOKEN:?Set verifier role token from secret manager}"
: "${SKILLCRED_REVOKER_TOKEN:?Set revoker role token from secret manager}"

for command in curl python uvicorn; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done
if [[ -n "${SKILLCRED_PRIVATE_KEY_B64:-}" ]]; then
  echo "Recovery test requires wallet-backed key storage; unset SKILLCRED_PRIVATE_KEY_B64." >&2
  exit 2
fi

work="$(mktemp -d)"
RECOVERY_PID=""
cleanup() {
  if [[ -n "$RECOVERY_PID" ]]; then
    kill "$RECOVERY_PID" 2>/dev/null || true
    wait "$RECOVERY_PID" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

curl -fsS "$BASE_URL/health" > "$work/health.json"
curl -fsS "$BASE_URL/ready" > "$work/ready.json"
python - "$work/health.json" "$work/ready.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    health = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    readiness = json.load(stream)
assert health.get("ok") is True, health
assert readiness.get("ready") is True and readiness.get("signing_ready") is True, readiness
PY

curl -fsS -X POST "$BASE_URL/issue" \
  -H "Authorization: Bearer $SKILLCRED_ISSUER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"achievement_name":"Independent deployment smoke test","achievement_description":"Synthetic test credential only"}' \
  > "$work/credential.json"
curl -fsS "$BASE_URL/status-list" > "$work/status.json"
curl -fsS -X POST "$BASE_URL/verify" \
  -H "Authorization: Bearer $SKILLCRED_VERIFIER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary "$(python - "$work/credential.json" "$work/status.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    status = json.load(stream)
print(json.dumps({"credential": credential, "status_list_credential": status}))
PY
)" > "$work/verify-before.json"
python - "$work/verify-before.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result.get("valid") is True, result
PY

INDEX="$(python - "$work/credential.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
print(credential["credentialStatus"]["statusListIndex"])
PY
)"
curl -fsS -X POST "$BASE_URL/revoke" \
  -H "Authorization: Bearer $SKILLCRED_REVOKER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"status_list_index\":$INDEX}" > "$work/revoke.json"
curl -fsS "$BASE_URL/status-list" > "$work/status-revoked.json"
curl -fsS -X POST "$BASE_URL/verify" \
  -H "Authorization: Bearer $SKILLCRED_VERIFIER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary "$(python - "$work/credential.json" "$work/status-revoked.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    status = json.load(stream)
print(json.dumps({"credential": credential, "status_list_credential": status}))
PY
)" > "$work/verify-after.json"
python - "$work/verify-after.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result.get("signature_valid") is True, result
assert result.get("status") == "revoked" and result.get("valid") is False, result
PY

# Restore encrypted key and status state into an isolated directory, start a new
# API process there, then verify DID continuity, revoked status, and new issuance.
RECOVERY_DATA_DIR="$work/recovery-data"
mkdir -p "$RECOVERY_DATA_DIR"
for file in issuer-wallet.scw status-state.json; do
  [[ -f "$LIVE_DATA_DIR/$file" ]] || { echo "Recovery source is missing $LIVE_DATA_DIR/$file" >&2; exit 2; }
  cp -p "$LIVE_DATA_DIR/$file" "$RECOVERY_DATA_DIR/$file"
done
PORT="$(python - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
SKILLCRED_DATA_DIR="$RECOVERY_DATA_DIR" uvicorn skillcred.api:app --host 127.0.0.1 --port "$PORT" > "$work/recovery-api.log" 2>&1 &
RECOVERY_PID=$!
RECOVERY_URL="http://127.0.0.1:$PORT"
ready=0
for _ in $(seq 1 40); do
  if curl -fsS "$RECOVERY_URL/ready" > "$work/recovery-ready.json" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$RECOVERY_PID" 2>/dev/null; then
    cat "$work/recovery-api.log" >&2
    echo "Restored API process exited before readiness." >&2
    exit 1
  fi
  sleep 0.25
done
if [[ "$ready" != "1" ]]; then
  cat "$work/recovery-api.log" >&2
  echo "Restored API did not become ready within 10 seconds." >&2
  exit 1
fi

curl -fsS "$RECOVERY_URL/issuer" > "$work/recovery-issuer.json"
python - "$work/credential.json" "$work/recovery-issuer.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    issuer = json.load(stream)
assert credential["issuer"]["id"] == issuer["id"], "Restored issuer DID changed"
PY
curl -fsS "$RECOVERY_URL/status-list" > "$work/recovery-status.json"
curl -fsS -X POST "$RECOVERY_URL/verify" \
  -H "Authorization: Bearer $SKILLCRED_VERIFIER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary "$(python - "$work/credential.json" "$work/recovery-status.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    status = json.load(stream)
print(json.dumps({"credential": credential, "status_list_credential": status}))
PY
)" > "$work/recovery-check.json"
python - "$work/recovery-check.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result.get("signature_valid") is True and result.get("status") == "revoked", result
assert result.get("valid") is False, result
PY

curl -fsS -X POST "$RECOVERY_URL/issue" \
  -H "Authorization: Bearer $SKILLCRED_ISSUER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"achievement_name":"Restored issuer smoke test","achievement_description":"Synthetic recovery credential"}' \
  > "$work/recovered-new-credential.json"
curl -fsS "$RECOVERY_URL/status-list" > "$work/recovery-status-new.json"
curl -fsS -X POST "$RECOVERY_URL/verify" \
  -H "Authorization: Bearer $SKILLCRED_VERIFIER_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary "$(python - "$work/recovered-new-credential.json" "$work/recovery-status-new.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    credential = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    status = json.load(stream)
print(json.dumps({"credential": credential, "status_list_credential": status}))
PY
)" > "$work/recovered-new-check.json"
python - "$work/recovered-new-check.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result.get("valid") is True and result.get("status") == "active", result
PY

echo "PASS: independent HTTP issue/verify/revoke plus isolated API restore, issuer-DID continuity, status continuity and post-restore issuance"
