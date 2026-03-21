#!/bin/bash
set -e

echo "╔══════════════════════════════════════════╗"
echo "║  defense-kit v2 — Scan • Harden • Monitor ║"
echo "╚══════════════════════════════════════════╝"

# Check mounts
if [ ! -d "/defense-kit/target" ]; then
    echo "Warning: /defense-kit/target not mounted"
fi

if [ ! -d "/defense-kit/outputs" ]; then
    mkdir -p /defense-kit/outputs
fi

# If --scan flag passed, run quick scan
if [ "$1" = "--scan" ]; then
    shift
    defense-kit scan --output /defense-kit/outputs "$@"
    exit $?
fi

exec "$@"
