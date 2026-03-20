#!/bin/bash
# defense-kit quick scan — runs all scanners and generates summary

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET="${1:-/defense-kit/target}"
OUTPUT="/defense-kit/outputs/quick-scan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT"/{code,deps,secrets,containers}

echo -e "${BOLD}${CYAN}==========================================${NC}"
echo -e "${BOLD}${CYAN}  defense-kit Quick Scan${NC}"
echo -e "${BOLD}${CYAN}  Target: $TARGET${NC}"
echo -e "${BOLD}${CYAN}==========================================${NC}"
echo ""

# Code scan
echo -e "${BOLD}[1/5] Code scan (semgrep)...${NC}"
semgrep --config auto "$TARGET" --json -o "$OUTPUT/code/semgrep.json" --quiet 2>/dev/null
count=$(jq '.results | length' "$OUTPUT/code/semgrep.json" 2>/dev/null || echo 0)
echo -e "  Found: ${YELLOW}$count${NC} issues"

# Secret scan
echo -e "${BOLD}[2/5] Secret scan (gitleaks)...${NC}"
gitleaks detect --source "$TARGET" --report-path "$OUTPUT/secrets/gitleaks.json" --report-format json --no-banner 2>/dev/null
count=$(jq '. | length' "$OUTPUT/secrets/gitleaks.json" 2>/dev/null || echo 0)
echo -e "  Found: ${YELLOW}$count${NC} secrets"

# Dependency scan
echo -e "${BOLD}[3/5] Dependency scan (trivy)...${NC}"
trivy fs "$TARGET" --format json -o "$OUTPUT/deps/trivy.json" --quiet 2>/dev/null
count=$(jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' "$OUTPUT/deps/trivy.json" 2>/dev/null || echo 0)
echo -e "  Found: ${YELLOW}$count${NC} vulnerable dependencies"

# Dockerfile scan
echo -e "${BOLD}[4/5] Dockerfile scan (hadolint)...${NC}"
dockerfiles=$(find "$TARGET" -name "Dockerfile*" 2>/dev/null)
if [ -n "$dockerfiles" ]; then
    echo "$dockerfiles" | xargs -I{} hadolint {} 2>&1 | tee "$OUTPUT/containers/hadolint.txt"
    count=$(wc -l < "$OUTPUT/containers/hadolint.txt" 2>/dev/null || echo 0)
    echo -e "  Found: ${YELLOW}$count${NC} Dockerfile issues"
else
    echo -e "  ${GREEN}No Dockerfiles found${NC}"
fi

# Python scan
echo -e "${BOLD}[5/5] Python scan (bandit)...${NC}"
py_files=$(find "$TARGET" -name "*.py" 2>/dev/null | head -1)
if [ -n "$py_files" ]; then
    bandit -r "$TARGET" -f json -o "$OUTPUT/code/bandit.json" --quiet 2>/dev/null
    count=$(jq '.results | length' "$OUTPUT/code/bandit.json" 2>/dev/null || echo 0)
    echo -e "  Found: ${YELLOW}$count${NC} Python issues"
else
    echo -e "  ${GREEN}No Python files found${NC}"
fi

echo ""
echo -e "${BOLD}${CYAN}==========================================${NC}"
echo -e "  Results saved to: ${GREEN}$OUTPUT${NC}"
echo -e "${BOLD}${CYAN}==========================================${NC}"
