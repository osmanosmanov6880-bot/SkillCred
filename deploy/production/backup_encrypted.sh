#!/usr/bin/env bash
set -euo pipefail
: "${SKILLCRED_DATA_DIR:?Set SKILLCRED_DATA_DIR to the application data directory}"
: "${BACKUP_AGE_RECIPIENT:?Set BACKUP_AGE_RECIPIENT to a trusted age public recipient}"
command -v age >/dev/null || { echo "age binary is required for encrypted backups" >&2; exit 2; }
[[ -d "$SKILLCRED_DATA_DIR" ]] || { echo "data directory does not exist" >&2; exit 2; }
DEST="${1:-./backups}"
mkdir -p "$DEST"
chmod 700 "$DEST"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$DEST/.skillcred-${STAMP}.age.tmp"
trap 'rm -f "$TMP"' EXIT
umask 077
# Encrypt as data streams to age; no unencrypted tar file is written to disk.
tar -C "$SKILLCRED_DATA_DIR" --exclude='*.tmp' -czf - . | age -r "$BACKUP_AGE_RECIPIENT" > "$TMP"
mv "$TMP" "$DEST/skillcred-${STAMP}.tar.gz.age"
trap - EXIT
sha256sum "$DEST/skillcred-${STAMP}.tar.gz.age" > "$DEST/skillcred-${STAMP}.sha256"
printf '%s\n' "$DEST/skillcred-${STAMP}.tar.gz.age"
