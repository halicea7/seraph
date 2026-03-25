#!/usr/bin/env bash
# Seraph — Dev launcher
# Starts both backend (uvicorn) and frontend (vite) with a single command.
# Ctrl+C stops both.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$REPO_DIR/backend"
FRONTEND_DIR="$REPO_DIR/frontend"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

# Prefix each line of a stream with a colored tag
prefix() {
    local tag="$1" color="$2"
    while IFS= read -r line; do
        printf "${color}[%s]${RESET} %s\n" "$tag" "$line"
    done
}

echo -e "${GREEN}"
echo "  ███████╗███████╗██████╗  █████╗ ██████╗ ██╗  ██╗"
echo "  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║  ██║"
echo "  ███████╗█████╗  ██████╔╝███████║██████╔╝███████║"
echo "  ╚════██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██║"
echo "  ███████║███████╗██║  ██║██║  ██║██║     ██║  ██║"
echo "  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "  ${CYAN}Backend${RESET}  →  http://localhost:8000"
echo -e "  ${GREEN}Frontend${RESET} →  http://localhost:22123"
echo ""

# Install Python deps if needed
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo -e "${YELLOW}[setup] Installing Python dependencies...${RESET}"
    pip install -r "$REPO_DIR/requirements.txt" --break-system-packages -q
fi

# Install Node deps if needed
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo -e "${YELLOW}[setup] Installing Node dependencies...${RESET}"
    (cd "$FRONTEND_DIR" && npm install --silent)
fi

echo ""

# Check if msfrpcd is running, offer to start it
if ! pgrep -f msfrpcd > /dev/null 2>&1; then
    if command -v msfrpcd &> /dev/null; then
        echo -e "${YELLOW}[msf] msfrpcd not running. Starting on 127.0.0.1:55553...${RESET}"
        msfrpcd -P "${MSF_RPC_PASSWORD:-seraph}" -S -a 127.0.0.1 -p 55553 -f &
        sleep 3
        echo -e "${GREEN}[msf] msfrpcd started${RESET}"
    else
        echo -e "${YELLOW}[msf] Metasploit not installed — C2 module will be unavailable${RESET}"
    fi
else
    echo -e "${GREEN}[msf] msfrpcd already running${RESET}"
fi

# Kill all child processes on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}[dev] Shutting down...${RESET}"
    kill 0
}
trap cleanup EXIT INT TERM

# Start backend
(
    cd "$BACKEND_DIR"
    python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 2>&1 | prefix "backend" "$CYAN"
) &

# Small delay so backend starts first
sleep 1

# Start frontend
(
    cd "$FRONTEND_DIR"
    npm run dev 2>&1 | prefix "frontend" "$GREEN"
) &

# Wait for both
wait
