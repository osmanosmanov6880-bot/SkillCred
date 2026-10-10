#!/usr/bin/env bash
set -euo pipefail
: "${BACKUP_AGE_IDENTITY:?Set BACKUP_AGE_IDENTITY to a protected age identity file}"
BACKUP="${1:?usage: restore_encrypted.sh backup.tar.gz.age destination-dir}"
DEST="${2:?usage: restore_encrypted.sh backup.tar.gz.age destination-dir}"
command -v age >/dev/null || { echo "age binary is required" >&2; exit 2; }
[[ -f "$BACKUP" ]] || { echo "backup not found" >&2; exit 2; }
mkdir -p "$DEST"
chmod 700 "$DEST"
TMPDIR_PRIVATE="$(mktemp -d)"
chmod 700 "$TMPDIR_PRIVATE"
trap 'rm -rf "$TMPDIR_PRIVATE"' EXIT
age -d -i "$BACKUP_AGE_IDENTITY" "$BACKUP" > "$TMPDIR_PRIVATE/backup.tar.gz"
# Reject absolute paths and traversal before extracting the trusted archive.
if tar -tzf "$TMPDIR_PRIVATE/backup.tar.gz" | awk 'index($0,"../")==1 || $0 ~ /\/\.\.\// || $0 ~ /^\// {bad=1} END {exit bad ? 0 : 1}'; then
  echo "Unsafe path detected in backup; refusing restore" >&2
  exit 3
fi
tar -xzf "$TMPDIR_PRIVATE/backup.tar.gz" -C "$DEST"
printf 'Restored backup to %s. Verify wallet, client registry and status-list integrity before starting the API.\n' "$DEST"
