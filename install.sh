#!/usr/bin/env bash
#
# defense-kit local installer
#
# Usage:
#   ./install.sh                     # build + install + tools
#   ./install.sh --prefix /usr/local # install to /usr/local/bin
#   ./install.sh --no-tools          # skip external security tools
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${HOME}/.local"
INSTALL_TOOLS=true
BINARY_NAME="defense-kit"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --no-tools)
            INSTALL_TOOLS=false
            shift
            ;;
        --help|-h)
            echo "Usage: ./install.sh [--prefix /path] [--no-tools]"
            echo ""
            echo "Options:"
            echo "  --prefix PATH    Install to PATH/bin (default: ~/.local)"
            echo "  --no-tools       Skip installing external security tools (installed by default)"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

BIN_DIR="${PREFIX}/bin"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  defense-kit installer                       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check Go
info "Checking Go installation..."
if ! command -v go &>/dev/null; then
    fail "Go is not installed. Install Go 1.22+ from https://go.dev/dl/"
fi

GO_VERSION=$(go version | grep -oP '\d+\.\d+' | head -1)
info "Found Go ${GO_VERSION}"

# Build
info "Building defense-kit..."
cd "${REPO_DIR}/defense-kit-cli"

if ! go build -o "${BINARY_NAME}" ./cmd/defense-kit; then
    fail "Build failed"
fi
ok "Build successful"

# Install binary
info "Installing to ${BIN_DIR}/${BINARY_NAME}..."
mkdir -p "${BIN_DIR}"
mv "${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
chmod +x "${BIN_DIR}/${BINARY_NAME}"
ok "Installed: ${BIN_DIR}/${BINARY_NAME}"

# Create config directory
CONFIG_DIR="${HOME}/.config/defense-kit"
DATA_DIR="${HOME}/.defense-kit"
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}/outputs"

# Copy templates
if [ -d "${REPO_DIR}/defense-kit-cli/templates" ]; then
    mkdir -p "${DATA_DIR}/templates"
    cp -r "${REPO_DIR}/defense-kit-cli/templates/"* "${DATA_DIR}/templates/" 2>/dev/null || true
fi

# Copy policies
if [ -d "${REPO_DIR}/policies" ]; then
    mkdir -p "${DATA_DIR}/policies"
    cp -r "${REPO_DIR}/policies/"* "${DATA_DIR}/policies/" 2>/dev/null || true
fi

ok "Data directory: ${DATA_DIR}"

# Install external tools
if [ "${INSTALL_TOOLS}" = true ]; then
    echo ""
    info "Installing external security tools..."

    if command -v apt-get &>/dev/null; then
        info "Detected apt-based system"
        sudo apt-get update -qq

        TOOLS="rkhunter chkrootkit lynis clamav aide debsums nmap"
        for tool in ${TOOLS}; do
            if ! command -v "${tool}" &>/dev/null; then
                info "Installing ${tool}..."
                sudo apt-get install -y -qq "${tool}" 2>/dev/null && ok "${tool} installed" || warn "Failed to install ${tool}"
            else
                ok "${tool} already installed"
            fi
        done

        # Python tools
        if command -v pip3 &>/dev/null; then
            PIP_TOOLS="ssh-audit"
            for tool in ${PIP_TOOLS}; do
                if ! command -v "${tool}" &>/dev/null; then
                    info "Installing ${tool} via pip..."
                    pip3 install --break-system-packages "${tool}" 2>/dev/null && ok "${tool} installed" || warn "Failed to install ${tool}"
                else
                    ok "${tool} already installed"
                fi
            done
        fi
    else
        warn "Non-apt system detected. Install tools manually:"
        warn "  rkhunter chkrootkit lynis clamav aide debsums nmap ssh-audit"
    fi
fi

# Check PATH
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    echo ""
    warn "${BIN_DIR} is not in your PATH"
    echo "  Add this to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"${BIN_DIR}:\$PATH\""
fi

# Verify
echo ""
if command -v defense-kit &>/dev/null || [ -x "${BIN_DIR}/${BINARY_NAME}" ]; then
    ok "defense-kit installed successfully!"
    echo ""
    echo "  Quick start:"
    echo "    defense-kit scan                          # scan your system"
    echo "    defense-kit dashboard --port 8080 --open  # open dashboard"
    echo "    defense-kit tools check                   # check available tools"
    echo "    defense-kit schedule enable --interval 6h # auto-scan"
    echo ""
else
    fail "Installation verification failed"
fi
