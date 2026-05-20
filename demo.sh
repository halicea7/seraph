#!/usr/bin/env bash
# demo.sh — Seraph one-command demo launcher
#
# Starts Seraph + two vulnerable containers, seeds demo data, and creates a
# "Live Targets" project pointing at the running containers so you can scan
# them immediately from within Seraph.
#
# Requirements: docker (with compose plugin), curl, jq

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat <<'BANNER'
  ███████╗███████╗██████╗  █████╗ ██████╗ ██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║  ██║
  ███████╗█████╗  ██████╔╝███████║██████╔╝███████║
  ╚════██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██║
  ███████║███████╗██║  ██║██║  ██║██║     ██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
                    Demo Launcher
BANNER
echo -e "${RESET}"

COMPOSE_FILE="docker-compose.demo.yml"
API="http://localhost:8000/api/v1"
ADMIN_USER="admin"
ADMIN_PASS="seraph-demo"

# ── Helpers ───────────────────────────────────────────────────────────────────
info() { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

require() {
  command -v "$1" &>/dev/null || die "Required tool not found: $1. Please install it and retry."
}

# ── Preflight checks ──────────────────────────────────────────────────────────
require docker
require curl
require jq

docker info &>/dev/null           || die "Docker daemon is not running. Start Docker and retry."
docker compose version &>/dev/null || die "Docker Compose plugin not found. Install it and retry."

# ── Start containers ──────────────────────────────────────────────────────────
info "Pulling images and starting containers (may take a few minutes on first run)..."
docker compose -f "$COMPOSE_FILE" up -d --build

# ── Wait for backend ──────────────────────────────────────────────────────────
info "Waiting for Seraph backend..."
attempt=0
until curl -sf "$API/projects" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    die "Backend did not become healthy after 60 attempts.\nCheck logs: docker compose -f $COMPOSE_FILE logs backend"
  fi
  printf "."
  sleep 3
done
echo
ok "Backend is ready."

# ── First-run admin setup ─────────────────────────────────────────────────────
SETUP_REQUIRED=$(curl -sf "$API/auth/setup-required" | jq -r '.required // false')
if [ "$SETUP_REQUIRED" = "true" ]; then
  info "Creating admin account (first run)..."
  curl -sf -X POST "$API/auth/setup" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"full_name\":\"Demo Admin\"}" \
    >/dev/null
  ok "Admin account created."
fi

# ── Authenticate ──────────────────────────────────────────────────────────────
TOKEN=$(curl -sf -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
  | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || die "Login failed — check that credentials match an existing account."
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

# ── Seed demo data ────────────────────────────────────────────────────────────
info "Seeding demo projects and findings..."
SEEDED=$(curl -sf -X POST "$API/demo/seed" | jq -r '.ok // false')
if [ "$SEEDED" = "true" ]; then
  ok "Demo data seeded (3 projects, findings, credentials)."
else
  warn "Seed returned unexpected response — data may already be loaded."
fi

# ── Create live targets project ───────────────────────────────────────────────
info "Setting up live targets project..."

EXISTING=$(curl -sf "${AUTH[@]}" "$API/projects" \
  | jq -r '.[] | select(.name == "Demo Lab — Live Targets") | .id // empty')

if [ -n "$EXISTING" ]; then
  warn "Live targets project already exists — skipping."
else
  PROJECT_ID=$(curl -sf -X POST "$API/projects" \
    "${AUTH[@]}" \
    -d '{"name":"Demo Lab — Live Targets","description":"Vulnerable Docker containers running alongside Seraph. Use these as scan targets to test Seraph capabilities live."}' \
    | jq -r '.id')

  # DVWA — reachable as 'dvwa' on the shared Docker network from inside the backend container
  curl -sf -X POST "$API/projects/$PROJECT_ID/targets" \
    "${AUTH[@]}" \
    -d '{"hostname_or_ip":"dvwa","target_type":"web_app","ports":"80","notes":"Damn Vulnerable Web App — browse at http://localhost:8888 (admin/password)"}' \
    >/dev/null

  # Juice Shop
  curl -sf -X POST "$API/projects/$PROJECT_ID/targets" \
    "${AUTH[@]}" \
    -d '{"hostname_or_ip":"juiceshop","target_type":"web_app","ports":"3000","notes":"OWASP Juice Shop — browse at http://localhost:3001"}' \
    >/dev/null

  ok "Live targets project created."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Seraph demo stack is ready${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
echo -e "  ${BOLD}Seraph${RESET}          http://localhost:5173"
echo -e "  ${BOLD}Credentials${RESET}     ${ADMIN_USER} / ${ADMIN_PASS}"
echo
echo -e "  ${BOLD}Vulnerable targets${RESET}"
echo -e "    DVWA            http://localhost:8888   (admin / password)"
echo -e "    Juice Shop      http://localhost:3001"
echo
echo -e "  ${BOLD}In Seraph${RESET}"
echo -e "    - Open the '${BOLD}Demo Lab — Live Targets${RESET}' project to scan the containers"
echo -e "    - Three pre-loaded projects show example findings, reports, and credentials"
echo
echo -e "  ${BOLD}Teardown${RESET}"
echo -e "    docker compose -f ${COMPOSE_FILE} down -v"
echo
