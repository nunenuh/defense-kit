#!/usr/bin/env bash
#
# defense-kit remote installer
#
# Install via:
#   curl -sSL https://get.nunenuh.me/defense-kit | bash
#   wget -qO- https://get.nunenuh.me/defense-kit | bash
#
# Options (pass after -- when piping):
#   --prefix /path     Install to /path/bin (default: ~/.local)
#   --no-tools         Skip installing external security tools
#   --version TAG      Install specific version (default: latest)
#
set -euo pipefail

REPO="nunenuh/defense-kit"
GITHUB_URL="https://github.com/${REPO}"
PREFIX="${HOME}/.local"
INSTALL_TOOLS=true
VERSION="latest"
BINARY_NAME="defense-kit"
TMPDIR=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

cleanup() {
    if [ -n "${TMPDIR}" ] && [ -d "${TMPDIR}" ]; then
        rm -rf "${TMPDIR}"
    fi
}
trap cleanup EXIT

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
        --version)
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: curl -sSL https://get.nunenuh.me/defense-kit | bash -s -- [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --prefix PATH    Install to PATH/bin (default: ~/.local)"
            echo "  --no-tools       Skip installing external security tools (installed by default)"
            echo "  --version TAG    Install specific version (default: latest)"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

BIN_DIR="${PREFIX}/bin"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  defense-kit remote installer                ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             fail "Unsupported architecture: ${ARCH}" ;;
esac

case "${OS}" in
    linux)  ;;
    *)      fail "Unsupported OS: ${OS}. defense-kit currently supports Linux only." ;;
esac

info "Detected: ${OS}/${ARCH}"

# Check for required tools
for cmd in curl tar; do
    if ! command -v "${cmd}" &>/dev/null; then
        fail "${cmd} is required but not installed"
    fi
done

# Resolve version
if [ "${VERSION}" = "latest" ]; then
    info "Fetching latest release..."
    VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || echo "")

    # Fallback: try tags if no releases
    if [ -z "${VERSION}" ]; then
        VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/tags" 2>/dev/null | grep '"name"' | head -1 | cut -d'"' -f4 || echo "")
    fi

    # Fallback: use main
    if [ -z "${VERSION}" ]; then
        VERSION="main"
        warn "Could not determine latest version, using main branch"
    fi
fi

info "Version: ${VERSION}"

# Method 1: Try downloading pre-built binary from GitHub releases
RELEASE_URL="${GITHUB_URL}/releases/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
TMPDIR=$(mktemp -d)

info "Trying pre-built binary..."
if curl -sSLf -o "${TMPDIR}/defense-kit.tar.gz" "${RELEASE_URL}" 2>/dev/null; then
    info "Extracting..."
    tar -xzf "${TMPDIR}/defense-kit.tar.gz" -C "${TMPDIR}"
    # Archive may contain "defense-kit" or "defense-kit-{os}-{arch}"
    EXTRACTED=""
    if [ -f "${TMPDIR}/${BINARY_NAME}" ]; then
        EXTRACTED="${TMPDIR}/${BINARY_NAME}"
    elif [ -f "${TMPDIR}/${BINARY_NAME}-${OS}-${ARCH}" ]; then
        EXTRACTED="${TMPDIR}/${BINARY_NAME}-${OS}-${ARCH}"
    fi
    if [ -n "${EXTRACTED}" ]; then
        mkdir -p "${BIN_DIR}"
        mv "${EXTRACTED}" "${BIN_DIR}/${BINARY_NAME}"
        chmod +x "${BIN_DIR}/${BINARY_NAME}"
        ok "Installed pre-built binary"
    else
        fail "Binary not found in archive (looked for ${BINARY_NAME} and ${BINARY_NAME}-${OS}-${ARCH})"
    fi
else
    # Method 2: Build from source
    info "No pre-built binary available. Building from source..."

    if ! command -v go &>/dev/null; then
        fail "Go is required to build from source. Install Go 1.22+ from https://go.dev/dl/"
    fi

    GO_VERSION=$(go version | grep -oP '\d+\.\d+' | head -1)
    info "Found Go ${GO_VERSION}"

    info "Cloning repository..."
    git clone --depth 1 --branch "${VERSION}" "${GITHUB_URL}.git" "${TMPDIR}/defense-kit" 2>/dev/null || \
    git clone --depth 1 "${GITHUB_URL}.git" "${TMPDIR}/defense-kit"

    info "Building..."
    cd "${TMPDIR}/defense-kit/defense-kit-cli"
    go build -o "${BINARY_NAME}" ./cmd/defense-kit

    mkdir -p "${BIN_DIR}"
    mv "${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"
    chmod +x "${BIN_DIR}/${BINARY_NAME}"
    ok "Built and installed from source"

    # Copy templates and policies
    DATA_DIR="${HOME}/.defense-kit"
    mkdir -p "${DATA_DIR}/templates" "${DATA_DIR}/policies"
    cp -r templates/* "${DATA_DIR}/templates/" 2>/dev/null || true
    cp -r "${TMPDIR}/defense-kit/policies/"* "${DATA_DIR}/policies/" 2>/dev/null || true
fi

# Create data directories
DATA_DIR="${HOME}/.defense-kit"
CONFIG_DIR="${HOME}/.config/defense-kit"
mkdir -p "${DATA_DIR}/outputs" "${CONFIG_DIR}"

# Install external tools
if [ "${INSTALL_TOOLS}" = true ]; then
    echo ""
    info "Installing external security tools..."

    if command -v apt-get &>/dev/null; then
        info "Detected apt-based system"
        sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed (try running with sudo)"

        TOOLS="rkhunter chkrootkit lynis clamav aide debsums nmap"
        for tool in ${TOOLS}; do
            if ! command -v "${tool}" &>/dev/null; then
                info "Installing ${tool}..."
                sudo apt-get install -y -qq "${tool}" 2>/dev/null && ok "${tool}" || warn "Failed: ${tool}"
            else
                ok "${tool} (already installed)"
            fi
        done

        # Python tools
        if command -v pip3 &>/dev/null; then
            for tool in ssh-audit; do
                if ! command -v "${tool}" &>/dev/null; then
                    pip3 install --break-system-packages "${tool}" 2>/dev/null && ok "${tool}" || warn "Failed: ${tool}"
                else
                    ok "${tool} (already installed)"
                fi
            done
        fi

    elif command -v dnf &>/dev/null; then
        info "Detected dnf-based system (Fedora/RHEL)"
        sudo dnf install -y rkhunter lynis clamav nmap 2>/dev/null || warn "Some tools failed to install"

    elif command -v pacman &>/dev/null; then
        info "Detected pacman-based system (Arch)"
        sudo pacman -S --noconfirm rkhunter lynis clamav nmap 2>/dev/null || warn "Some tools failed to install"

    else
        warn "Could not detect package manager. Install tools manually:"
        warn "  rkhunter chkrootkit lynis clamav aide debsums nmap ssh-audit"
    fi
fi

# Check PATH
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    echo ""
    warn "${BIN_DIR} is not in your PATH"
    echo ""
    echo "  Add to ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"${BIN_DIR}:\$PATH\""
    echo ""
    echo "  Or install system-wide:"
    echo "    sudo mv ${BIN_DIR}/${BINARY_NAME} /usr/local/bin/"
fi

# Done
echo ""
echo -e "${GREEN}${BOLD}defense-kit installed successfully!${NC}"
echo ""
echo "  Version:  $(${BIN_DIR}/${BINARY_NAME} --version 2>/dev/null || echo "${VERSION}")"
echo "  Binary:   ${BIN_DIR}/${BINARY_NAME}"
echo "  Data:     ${DATA_DIR}/"
echo "  Config:   ${CONFIG_DIR}/"
echo ""
echo "  Quick start:"
echo "    defense-kit scan                          # scan your system"
echo "    defense-kit dashboard --port 8080 --open  # open dashboard"
echo "    defense-kit tools check                   # check available tools"
echo ""
echo "  Documentation: ${GITHUB_URL}"
echo ""
