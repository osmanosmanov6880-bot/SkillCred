#!/bin/sh
set -eu

# Render mounts the persistent disk at runtime, so image-build ownership does
# not apply to the mounted directory. Prepare permissions as root, then drop
# privileges before starting the API process.
DATA_DIR="${SKILLCRED_DATA_DIR:-/var/lib/skillcred}"
mkdir -p "$DATA_DIR"
chown -R skillcred:skillcred "$DATA_DIR"
chmod 700 "$DATA_DIR"

PORT_VALUE="${PORT:-8000}"
exec setpriv --reuid=skillcred --regid=skillcred --init-groups \
  uvicorn skillcred.api:app --host 0.0.0.0 --port "$PORT_VALUE"
