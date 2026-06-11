#!/usr/bin/env bash
# Seraph HTTPS setup — run once to enable HTTPS for local development.
# Uses mkcert to create a locally-trusted certificate so browsers trust it
# without any security warnings.
#
# After running this script, restart dev.sh — it will auto-detect the certs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${CYAN}[https] Setting up local HTTPS for Seraph...${RESET}"

# ── 1. Install mkcert if needed ───────────────────────────────────────────────

if command -v apt-get &>/dev/null; then
    # libnss3-tools provides certutil, which mkcert needs to trust the CA in
    # Chromium-based browsers (Brave, Chrome) and Firefox on Linux.
    echo -e "${CYAN}[https] Installing libnss3-tools (required for Brave/Chrome trust)...${RESET}"
    sudo apt-get install -y libnss3-tools -q
fi

if ! command -v mkcert &>/dev/null; then
    echo -e "${YELLOW}[https] mkcert not found — installing...${RESET}"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -q && sudo apt-get install -y mkcert
    elif command -v brew &>/dev/null; then
        brew install mkcert
    else
        echo -e "${YELLOW}[https] Could not auto-install mkcert."
        echo -e "  Install it manually: https://github.com/FiloSottile/mkcert#installation"
        echo -e "  Then re-run this script.${RESET}"
        exit 1
    fi
fi

# ── 2. Install the local CA into the system + browser trust stores ────────────

echo -e "${CYAN}[https] Installing local CA (you may be prompted for sudo)...${RESET}"
mkcert -install

# ── 3. Generate certificate for localhost + LAN ──────────────────────────────

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Include the host's LAN IPs + hostname as SANs so the cert is also valid when a
# SeraphElectron app (or browser) connects from another machine via the host IP
# — e.g. https://192.168.1.50:8000 — not just https://localhost:8000.
EXTRA_SANS=""
for ip in $(hostname -I 2>/dev/null || true); do
    EXTRA_SANS="$EXTRA_SANS $ip"
done
HOST_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
[ -n "${HOST_FQDN:-}" ] && EXTRA_SANS="$EXTRA_SANS $HOST_FQDN"
# macOS fallback for the primary LAN IP.
if [ -z "${EXTRA_SANS// /}" ] && command -v ipconfig &>/dev/null; then
    MAC_IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
    [ -n "${MAC_IP:-}" ] && EXTRA_SANS="$MAC_IP"
fi

echo -e "${CYAN}[https] Certificate names: localhost 127.0.0.1 ::1${EXTRA_SANS}${RESET}"
# shellcheck disable=SC2086
mkcert -key-file localhost-key.pem -cert-file localhost.pem localhost 127.0.0.1 ::1 $EXTRA_SANS

# The Docker image runs as a non-root user (uid 1001) and mounts certs/ read-only,
# so the cert + key must be world-readable for the container to load them.
chmod 0644 localhost.pem localhost-key.pem

echo ""
echo -e "${GREEN}[https] Done! Certificates written to seraph/certs/${RESET}"
echo ""
echo -e "  ${CYAN}localhost.pem${RESET}      — certificate"
echo -e "  ${CYAN}localhost-key.pem${RESET}  — private key"
echo ""
echo -e "${GREEN}[https] Native (dev.sh):  restart it — certs are auto-detected.${RESET}"
echo -e "${GREEN}[https] Docker:           run ./setup.sh — the container starts on HTTPS.${RESET}"
echo -e "${GREEN}[https] Access at: https://localhost:8000  (or https://<this-host-ip>:8000 from the LAN)${RESET}"
echo ""
echo -e "${YELLOW}[https] NOTE: Fully quit and relaunch Brave/Chrome for the CA trust to take effect.${RESET}"
echo -e "${YELLOW}[https] LAN clients on OTHER machines must trust this machine's mkcert root CA:${RESET}"
echo -e "${YELLOW}        copy \"\$(mkcert -CAROOT)/rootCA.pem\" to the client and install it in its"
echo -e "${YELLOW}        system/browser trust store (or accept the browser warning once).${RESET}"
