#!/usr/bin/env bash
# Seraph container launcher.
#
#   • Starts uvicorn with a single worker, always.
#   • Auto-enables HTTPS when a cert + key are mounted at /certs (override the
#     paths with SERAPH_SSL_CERTFILE / SERAPH_SSL_KEYFILE). No certs → plain HTTP.
#
# Generate certs on the host with ./setup-https.sh, then mount ./certs:/certs:ro
# (docker-compose.yml already does this). TLS is detected on container start.
set -e

CERT="${SERAPH_SSL_CERTFILE:-/certs/localhost.pem}"
KEY="${SERAPH_SSL_KEYFILE:-/certs/localhost-key.pem}"

ssl_args=()
if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  if [ -r "$CERT" ] && [ -r "$KEY" ]; then
    echo "[entrypoint] TLS certs found ($CERT) — starting HTTPS on :8000"
    ssl_args=(--ssl-certfile "$CERT" --ssl-keyfile "$KEY")
  else
    echo "[entrypoint] WARNING: certs exist at $CERT but are not readable by uid $(id -u) — starting HTTP." >&2
    echo "[entrypoint]          Fix on the host with: chmod 0644 certs/*.pem" >&2
  fi
else
  echo "[entrypoint] No TLS certs at $CERT — starting HTTP on :8000"
fi

echo "[entrypoint] Running database migrations…"
python -c "from database import create_tables; create_tables()"

# Single worker, unconditionally. The scheduler, listener manager and
# cve_watcher all run in-process (APScheduler jobs + in-memory registries) —
# a second uvicorn worker would mean a second copy of each of them, each
# firing the same cron scans and competing for the same SQLite file. This
# used to flip to --workers 4 when PRODUCTION=1; don't restore that until
# those background jobs move out of the API process (see CLAUDE.md follow-up
# notes) into a real worker process.
worker_args=(--workers 1)

exec uvicorn main:app --host 0.0.0.0 --port 8000 "${worker_args[@]}" "${ssl_args[@]}"
