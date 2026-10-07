#!/usr/bin/env bash
# =========================================================
# XSSHunter — Installer + Runner
# Author : ATHEX BLACK HAT
# Version: 0.1.0
# License: MIT
# =========================================================

set -e  # exit on error

# ---------------------------------------------------------
# Colors
# ---------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
GO_CORE_DIR="$SCRIPT_DIR/go-core"
PY_BRAIN_DIR="$SCRIPT_DIR/py-brain"
VENV_DIR="$SCRIPT_DIR/venv"
BINARY="$SCRIPT_DIR/xsshunter-core"

GO_PORT=8080
CB_PORT=8888

# ---------------------------------------------------------
# ASCII Banner
# ---------------------------------------------------------
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
 __  __ ____  ____  _   _             _
 \ \/ // ___|/ ___|| | | |_   _ _ __ | |_ ___ _ __
  \  / \___ \\___ \| |_| | | | | '_ \| __/ _ \ '__|
  /  \  ___) |___) |  _  | |_| | | | | ||  __/ |
 /_/\_\|____/|____/|_| |_|\__,_|_| |_|\__\___|_|
EOF
    echo -e "${NC}"
    echo -e "        ${BOLD}Advanced XSS Hunter${NC}  •  ${MAGENTA}Go + Python Hybrid${NC}"
    echo -e "        ${DIM}Author : ATHEX BLACK HAT${NC}"
    echo -e "        ${DIM}Version: 0.1  |  License: MIT${NC}"
    echo -e "        ${DIM}Modules: crawler • injector • callback • waf${NC}"
    echo -e "        ${DIM}         context • payloads • dom • report${NC}"
    echo
}

# ---------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------
log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "${RED}[x]${NC} $1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}\n"; }

# ---------------------------------------------------------
# Check command exists
# ---------------------------------------------------------
need_cmd() {
    if ! command -v "$1" &> /dev/null; then
        log_err "'$1' not found. Please install it first."
        exit 1
    fi
}

# ---------------------------------------------------------
# Detect OS
# ---------------------------------------------------------
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="mac";;
        *)          OS="unknown";;
    esac
    log_info "OS detected: $OS"
}

# ---------------------------------------------------------
# 1. Dependency checks
# ---------------------------------------------------------
check_deps() {
    log_step "Checking dependencies"

    need_cmd go || {
        log_err "Go is required. Install: https://go.dev/dl/"
        exit 1
    }
    log_ok "Go: $(go version | awk '{print $3}')"

    need_cmd python3 || {
        log_err "Python 3 is required."
        exit 1
    }
    log_ok "Python: $(python3 --version)"

    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        log_err "pip3 is required."
        exit 1
    fi
    log_ok "pip: available"

    if [ ! -f "$SCRIPT_DIR/payloads.yaml" ]; then
        log_err "payloads.yaml not found in $SCRIPT_DIR"
        exit 1
    fi
    log_ok "payloads.yaml: found"

    if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
        log_err "requirements.txt not found in $SCRIPT_DIR"
        exit 1
    fi
    log_ok "requirements.txt: found"
}

# ---------------------------------------------------------
# 2. Build Go core
# ---------------------------------------------------------
build_go() {
    log_step "Building Go core"

    cd "$SCRIPT_DIR"

    log_info "Running 'go mod tidy'..."
    go mod tidy > /dev/null 2>&1 || {
        log_warn "go mod tidy failed (may be offline). Continuing..."
    }

    log_info "Building xsshunter-core..."
    if go build -o "$BINARY" ./go-core; then
        log_ok "Binary built: $BINARY"
        chmod +x "$BINARY"
    else
        log_err "Go build failed."
        exit 1
    fi
}

# ---------------------------------------------------------
# 3. Setup Python venv + install
# ---------------------------------------------------------
setup_python() {
    log_step "Setting up Python environment"

    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating venv at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
    else
        log_info "venv already exists"
    fi

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    log_info "Upgrading pip..."
    pip install --quiet --upgrade pip

    log_info "Installing Python dependencies..."
    if pip install --quiet -r "$SCRIPT_DIR/requirements.txt"; then
        log_ok "Python deps installed"
    else
        log_err "pip install failed."
        exit 1
    fi

    # Playwright browser
    if python -c "import playwright" &> /dev/null; then
        log_info "Installing Playwright Chromium (this may take a moment)..."
        python -m playwright install chromium > /dev/null 2>&1 && \
            log_ok "Playwright Chromium ready" || \
            log_warn "Playwright install failed (DOM verify may not work)"
    fi
}

# ---------------------------------------------------------
# 4. Start Go core in background
# ---------------------------------------------------------
start_go_core() {
    log_step "Starting Go core"

    # Kill existing on same ports
    if command -v lsof &> /dev/null; then
        lsof -ti:$GO_PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        lsof -ti:$CB_PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi

    # Launch in background
    nohup "$BINARY" --port $GO_PORT --callback-port $CB_PORT \
        > "$SCRIPT_DIR/go-core.log" 2>&1 &
    GO_PID=$!
    echo "$GO_PID" > "$SCRIPT_DIR/.go-core.pid"

    log_info "Go core PID: $GO_PID"
    log_info "Waiting for server to come up..."

    # Wait for health
    for i in $(seq 1 20); do
        if curl -s "http://127.0.0.1:$GO_PORT/health" > /dev/null 2>&1; then
            log_ok "Go core is up: http://127.0.0.1:$GO_PORT"
            log_ok "Callback server: http://127.0.0.1:$CB_PORT"
            return 0
        fi
        sleep 0.5
    done

    log_err "Go core failed to start. Check $SCRIPT_DIR/go-core.log"
    exit 1
}

# ---------------------------------------------------------
# 5. Trap cleanup
# ---------------------------------------------------------
cleanup() {
    echo
    log_info "Cleaning up..."
    if [ -f "$SCRIPT_DIR/.go-core.pid" ]; then
        local pid
        pid=$(cat "$SCRIPT_DIR/.go-core.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            log_ok "Stopped Go core (PID: $pid)"
        fi
        rm -f "$SCRIPT_DIR/.go-core.pid"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------
# 6. Show help / usage
# ---------------------------------------------------------
show_usage() {
    echo
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  ${GREEN}./install.sh${NC}                       # install only"
    echo -e "  ${GREEN}./install.sh scan -u <URL>${NC}         # install + scan"
    echo -e "  ${GREEN}./install.sh banner${NC}                # show banner + info"
    echo -e "  ${GREEN}./install.sh payloads --list${NC}       # list payload categories"
    echo -e "  ${GREEN}./install.sh callback watch${NC}        # live blind XSS"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ./install.sh scan -u https://target.com -o report.json"
    echo -e "  ./install.sh scan -u https://target.com -H 'Cookie: s=x' --dom"
    echo
}

# ---------------------------------------------------------
# 7. Run the CLI
# ---------------------------------------------------------
run_tool() {
    log_step "Launching XSSHunter CLI"

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    cd "$PY_BRAIN_DIR"

    # If no args → show help
    if [ $# -eq 0 ]; then
        python main.py --help
        return
    fi

    # Run with given args
    python main.py "$@"
}

# ---------------------------------------------------------
# 8. Main
# ---------------------------------------------------------
main() {
    print_banner

    detect_os
    check_deps
    build_go
    setup_python
    start_go_core

    echo
    log_ok "Installation complete!"
    echo

    # If user passed args, run tool with those; else show usage
    if [ $# -gt 0 ]; then
        run_tool "$@"
    else
        show_usage
        echo -e "${DIM}Tip: Run './install.sh scan -u https://your-target.com'${NC}"
    fi

    echo
    log_info "Go core is still running in background (PID: $(cat "$SCRIPT_DIR/.go-core.pid" 2>/dev/null || echo '?'))"
    log_info "Stop it manually: kill \$(cat .go-core.pid)"
    log_info "Logs: $SCRIPT_DIR/go-core.log"
    echo

    # Detach trap — let Go core keep running after script exits
    trap - EXIT
}

# ---------------------------------------------------------
# Entry
# ---------------------------------------------------------
main "$@"