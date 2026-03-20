#!/bin/bash

echo ""
echo "============================================"
echo "  defense-kit"
echo "  Scan • Harden • Monitor"
echo "============================================"
echo ""

if mountpoint -q /defense-kit/target 2>/dev/null; then
    file_count=$(find /defense-kit/target -type f 2>/dev/null | wc -l)
    echo "[*] /defense-kit/target mounted ($file_count files)"
else
    echo "[!] /defense-kit/target not mounted"
    echo "    Mount with: -v /path/to/code:/defense-kit/target:ro"
fi

if mountpoint -q /defense-kit/outputs 2>/dev/null; then
    echo "[*] /defense-kit/outputs mounted — findings will persist"
else
    echo "[!] /defense-kit/outputs not mounted"
fi

echo ""

if [ "$1" = "--scan" ]; then
    echo "Running quick scan..."
    bash /defense-kit/tools/scripts/quick-scan.sh
    exit $?
fi

exec "$@"
