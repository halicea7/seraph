#!/usr/bin/env bash
# Seraph — one-command setup.
#
#   ./setup.sh
#
# Brings up the all-in-one container (web UI + API + all tools) on a single port,
# backed by SQLite. Generates a .env with strong secrets on first run; safe to
# re-run (never overwrites existing values). No prompts, no manual editing.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
info()  { printf "${CYAN}[setup]${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}[setup]${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}[setup]${RESET} %s\n" "$1"; }
die()   { printf "${RED}[setup] ERROR:${RESET} %s\n" "$1" >&2; exit 1; }

printf "${GREEN}"
echo "  ███████╗███████╗██████╗  █████╗ ██████╗ ██╗  ██╗"
echo "  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║  ██║"
echo "  ███████╗█████╗  ██████╔╝███████║██████╔╝███████║"
echo "  ╚════██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██║"
echo "  ███████║███████╗██║  ██║██║  ██║██║     ██║  ██║"
echo "  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝"
printf "${RESET}\n"

# ── 1. Require Docker + Compose ───────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it: https://docs.docker.com/get-docker/"
if ! docker info >/dev/null 2>&1; then
  die "Docker is installed but the daemon isn't reachable. Start Docker (or run with sufficient permissions) and retry."
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Docker Compose not found. Install Compose v2: https://docs.docker.com/compose/install/"
fi

# ── 2. Secret generator ───────────────────────────────────────────────────────
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# Fill KEY in .env only when it's missing or blank — never clobber a real value.
set_env_if_blank() {
  local key="$1" val="$2" file=".env"
  if grep -qE "^${key}=.+" "$file"; then
    return 0
  fi
  if grep -qE "^${key}=" "$file"; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|" "$file" && rm -f "${file}.bak"
  else
    printf '%s=%s\n' "$key" "$val" >> "$file"
  fi
  ok "Generated ${key}"
}

# ── 3. Ensure .env + secrets ──────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  info "Created .env from .env.example"
else
  info "Using existing .env (existing values are preserved)"
fi

set_env_if_blank "SERAPH_SECRET_KEY"  "$(gen_secret)"
set_env_if_blank "MSF_RPC_PASSWORD"   "$(gen_secret)"
set_env_if_blank "POSTGRES_PASSWORD"  "$(gen_secret)"

PORT="$(grep -E '^SERAPH_PORT=' .env 2>/dev/null | cut -d= -f2- || true)"
PORT="${PORT:-8000}"

# ── 3b. TLS? If certs exist (from ./setup-https.sh), the container serves HTTPS.
SCHEME="http"
CURL_TLS=""
if [ -f certs/localhost.pem ] && [ -f certs/localhost-key.pem ]; then
  SCHEME="https"
  CURL_TLS="-k"   # mkcert CA isn't in this script's trust path; -k for the health probe only
  # The container runs as uid 1001 and mounts certs read-only — make them readable.
  chmod 0644 certs/localhost.pem certs/localhost-key.pem 2>/dev/null || true
  info "TLS certs found in certs/ — Seraph will start over HTTPS."
fi
URL="${SCHEME}://localhost:${PORT}"

# ── 4. Build & start ──────────────────────────────────────────────────────────
info "Building and starting Seraph (first run pulls all tools — this can take several minutes)..."
$COMPOSE up -d --build

# ── 5. Wait for health ────────────────────────────────────────────────────────
info "Waiting for Seraph to become ready..."
ready=false
for _ in $(seq 1 60); do
  if curl -fsS $CURL_TLS "${URL}/api/v1/auth/setup-required" >/dev/null 2>&1; then
    ready=true
    break
  fi
  printf "."
  sleep 3
done
printf "\n"

# Best-effort LAN IP, so a SeraphElectron app on another machine knows where to point.
HOST_IP="$( (hostname -I 2>/dev/null || true) | awk '{print $1}')"
[ -z "${HOST_IP:-}" ] && HOST_IP="$( (ipconfig getifaddr en0 2>/dev/null || true) )"

if [ "$ready" = true ]; then
  ok "Seraph API is up (${SCHEME^^})."
  echo ""
  printf "  ${CYAN}Connect the SeraphElectron desktop app:${RESET}\n"
  echo "     On the Connect screen, enter the backend URL:"
  printf "       ${GREEN}${URL}${RESET}   (same machine)\n"
  [ -n "${HOST_IP:-}" ] && printf "       ${GREEN}${SCHEME}://${HOST_IP}:${PORT}${RESET}   (from another machine on your network)\n"
  echo "     (CORS already allows the Electron app — no extra config needed.)"
  echo "     Create your admin account on the app's First-Run screen."
  echo ""
  printf "  ${GREEN}➜  API docs:  ${URL}/docs${RESET}\n"
  if [ "$SCHEME" = "https" ]; then
    echo ""
    printf "  ${YELLOW}LAN clients on other machines must trust this host's mkcert root CA${RESET}\n"
    printf "  ${YELLOW}(copy \"\$(mkcert -CAROOT)/rootCA.pem\" to them) or accept the warning once.${RESET}\n"
  else
    echo ""
    printf "  ${CYAN}Want HTTPS?${RESET}  run ${GREEN}./setup-https.sh${RESET} then re-run ${GREEN}./setup.sh${RESET}\n"
  fi
  echo ""
  echo "  Logs:  $COMPOSE logs -f"
  echo "  Stop:  $COMPOSE down        (data persists in the seraph_data volume)"
else
  warn "Seraph didn't answer health checks yet. It may still be starting — check the logs:"
  echo "     $COMPOSE logs -f"
  echo "  Then point the SeraphElectron app at ${URL} (API docs at ${URL}/docs)."
fi
