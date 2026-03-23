#!/usr/bin/env bash
#
# defense-kit uninstaller
#
# Usage:
#   ./uninstall.sh              # remove binary + data
#   ./uninstall.sh --keep-data  # remove binary only
#
set -euo pipefail

BINARY_NAME="defense-kit"
KEEP_DATA=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-data) KEEP_DATA=true; shift ;;
        *) shift ;;
    esac
done

echo ""
echo "defense-kit uninstaller"
echo ""

# Remove binary
for dir in "${HOME}/.local/bin" "/usr/local/bin" "/usr/bin"; do
    if [ -f "${dir}/${BINARY_NAME}" ]; then
        info "Removing ${dir}/${BINARY_NAME}"
        rm -f "${dir}/${BINARY_NAME}" 2>/dev/null || sudo rm -f "${dir}/${BINARY_NAME}"
        ok "Binary removed"
    fi
done

# Disable scheduled scans
if command -v systemctl &>/dev/null; then
    systemctl --user disable --now defense-kit.timer 2>/dev/null || true
    rm -f "${HOME}/.config/systemd/user/defense-kit.service" 2>/dev/null || true
    rm -f "${HOME}/.config/systemd/user/defense-kit.timer" 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
fi

# Remove cron entry
if command -v crontab &>/dev/null; then
    crontab -l 2>/dev/null | grep -v "defense-kit" | crontab - 2>/dev/null || true
fi

# Remove data
if [ "${KEEP_DATA}" = false ]; then
    for dir in "${HOME}/.defense-kit" "${HOME}/.config/defense-kit"; do
        if [ -d "${dir}" ]; then
            info "Removing ${dir}"
            rm -rf "${dir}"
            ok "Removed"
        fi
    done
else
    info "Keeping data at ~/.defense-kit and ~/.config/defense-kit"
fi

echo ""
ok "defense-kit uninstalled"
echo ""
