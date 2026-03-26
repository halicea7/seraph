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

# ── Preflight checks ──────────────────────────────────────────────────────────

# Node.js >= 18 required (Vite uses top-level await)
if ! command -v node &>/dev/null; then
    echo -e "${YELLOW}[preflight] ERROR: Node.js not found. Install Node 18+: https://nodejs.org${RESET}"
    exit 1
fi
NODE_MAJOR="$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')"
if [ "$NODE_MAJOR" -lt 18 ]; then
    echo -e "${YELLOW}[preflight] ERROR: Node.js ${NODE_MAJOR} detected — Node 18+ is required.${RESET}"
    if command -v apt-get &>/dev/null; then
        echo -e "${YELLOW}[preflight] Install via NodeSource:${RESET}"
        echo -e "${YELLOW}[preflight]   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -${RESET}"
        echo -e "${YELLOW}[preflight]   sudo apt-get install -y nodejs${RESET}"
    else
        echo -e "${YELLOW}[preflight]   https://nodejs.org/en/download${RESET}"
    fi
    exit 1
fi

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

# Find a compatible Python (pydantic-core requires <= 3.12)
_find_python() {
    for candidate in python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &>/dev/null; then
            if "$candidate" -c "import sys; exit(0 if sys.version_info < (3, 13) else 1)" 2>/dev/null; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

VENV_DIR="$REPO_DIR/.venv"

# If venv exists but was built with an incompatible Python, remove it
if [ -d "$VENV_DIR" ]; then
    VENV_PY="$VENV_DIR/bin/python3"
    if ! "$VENV_PY" -c "import sys; exit(0 if sys.version_info < (3, 13) else 1)" 2>/dev/null; then
        echo -e "${YELLOW}[setup] Existing venv uses incompatible Python — recreating...${RESET}"
        rm -rf "$VENV_DIR"
    fi
fi

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    PYTHON_BIN="$(_find_python || true)"
    if [ -z "$PYTHON_BIN" ]; then
        echo -e "${YELLOW}[setup] ERROR: Python 3.12 or earlier is required but not found.${RESET}"
        echo -e "${YELLOW}[setup] Install it from https://python.org/downloads or via Homebrew:${RESET}"
        echo -e "${YELLOW}[setup]   brew install python@3.12${RESET}"
        exit 1
    fi
    echo -e "${CYAN}[setup] Creating venv with $PYTHON_BIN ($("$PYTHON_BIN" --version))...${RESET}"
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR" 2>/tmp/seraph_venv_err; then
        echo -e "${YELLOW}[setup] ERROR: Failed to create virtual environment.${RESET}"
        cat /tmp/seraph_venv_err
        # Common fix on Debian/Ubuntu
        if command -v apt-get &>/dev/null; then
            PY_TAG="$(${PYTHON_BIN} -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
            echo -e "${YELLOW}[setup] Try: sudo apt-get install -y python${PY_TAG}-venv${RESET}"
        fi
        exit 1
    fi
    echo -e "${GREEN}[setup] Venv created at .venv${RESET}"
fi

# Activate venv
if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo -e "${YELLOW}[setup] ERROR: Venv activation script not found at $VENV_DIR/bin/activate${RESET}"
    echo -e "${YELLOW}[setup] Delete .venv and re-run dev.sh${RESET}"
    exit 1
fi
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
