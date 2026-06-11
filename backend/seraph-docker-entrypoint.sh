#!/usr/bin/env bash
# Seraph container launcher.
#
#   • Starts uvicorn (single worker by default; --workers 4 when PRODUCTION=1).
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

# Single worker keeps SQLite from hitting "database is locked"; PRODUCTION=1
# (Postgres prod stack) scales out to 4.
if [ "${PRODUCTION:-0}" = "1" ]; then
  worker_args=(--workers 4)
else
  worker_args=(--workers 1)
fi

exec uvicorn main:app --host 0.0.0.0 --port 8000 "${worker_args[@]}" "${ssl_args[@]}"
