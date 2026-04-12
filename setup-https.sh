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

# ── 3. Generate certificate for localhost ────────────────────────────────────

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

mkcert -key-file localhost-key.pem -cert-file localhost.pem localhost 127.0.0.1 ::1

echo ""
echo -e "${GREEN}[https] Done! Certificates written to seraph/certs/${RESET}"
echo ""
echo -e "  ${CYAN}localhost.pem${RESET}      — certificate"
echo -e "  ${CYAN}localhost-key.pem${RESET}  — private key"
echo ""
echo -e "${GREEN}[https] Restart dev.sh — it will pick up the certs automatically.${RESET}"
echo -e "${GREEN}[https] Access Seraph at: https://localhost:8000 (production build)${RESET}"
echo -e "${GREEN}[https]                or: https://localhost:22123 (dev server)${RESET}"
echo ""
echo -e "${YELLOW}[https] NOTE: Fully quit and relaunch Brave/Chrome for the CA trust to take effect.${RESET}"
