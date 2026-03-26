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

# Create venv if it doesn't exist
VENV_DIR="$REPO_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[setup] Creating Python virtual environment...${RESET}"
    # pydantic-core requires Python <= 3.12; prefer 3.12 then 3.11 then system python3
    PYTHON_BIN=""
    for candidate in python3.12 python3.11 python3; do
        if command -v "$candidate" &>/dev/null; then
            PY_VER="$("$candidate" -c 'import sys; print(sys.version_info[:2])')"
            if [[ "$PY_VER" < "(3, 13)" ]]; then
                PYTHON_BIN="$candidate"
                break
            fi
        fi
    done
    if [ -z "$PYTHON_BIN" ]; then
        echo -e "${YELLOW}[setup] Warning: could not find Python 3.12 or earlier. Trying system python3.${RESET}"
        echo -e "${YELLOW}[setup] If setup fails, install Python 3.12: https://python.org/downloads${RESET}"
        PYTHON_BIN="python3"
    fi
    echo -e "${CYAN}[setup] Using $PYTHON_BIN ($("$PYTHON_BIN" --version))${RESET}"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo -e "${GREEN}[setup] Venv created at .venv${RESET}"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Install Python deps if needed
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo -e "${YELLOW}[setup] Installing Python dependencies...${RESET}"
    pip install -r "$REPO_DIR/requirements.txt" -q
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

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}[dev] Shutting down...${RESET}"

    # Stop frontend
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo -e "${YELLOW}[dev] Stopping frontend (pid $FRONTEND_PID)...${RESET}"
        kill "$FRONTEND_PID" 2>/dev/null
        wait "$FRONTEND_PID" 2>/dev/null
    fi

    # Stop backend and any child reloader processes
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo -e "${YELLOW}[dev] Stopping backend (pid $BACKEND_PID)...${RESET}"
        kill "$BACKEND_PID" 2>/dev/null
        wait "$BACKEND_PID" 2>/dev/null
    fi

    # Release ports in case anything is still holding them
    fuser -k 8000/tcp 2>/dev/null || true
    fuser -k 22123/tcp 2>/dev/null || true

    echo -e "${GREEN}[dev] Done.${RESET}"
}
trap cleanup EXIT INT TERM

# Start backend
(
    cd "$BACKEND_DIR"
    python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 2>&1 | prefix "backend" "$CYAN"
) &
BACKEND_PID=$!

# Wait for backend to be ready before starting frontend
echo -e "${CYAN}[dev] Waiting for backend...${RESET}"
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/api/v1/auth/setup-required > /dev/null 2>&1; then
        echo -e "${GREEN}[dev] Backend ready${RESET}"
        break
    fi
    sleep 1
done

# Start frontend
(
    cd "$FRONTEND_DIR"
    npm run dev 2>&1 | prefix "frontend" "$GREEN"
) &
FRONTEND_PID=$!

# Wait for both
wait
