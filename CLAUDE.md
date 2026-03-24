# defense-kit

Defensive security toolkit for Linux. Go binary with 38 scanners, 4 hardeners, local dashboard.

## Setup

```bash
cd defense-kit-cli && make build
# Or: ./install.sh
```

## Usage

```bash
defense-kit scan                          # full audit
defense-kit scan --profile workstation    # laptop preset
defense-kit harden --dry-run              # preview fixes
defense-kit dashboard --port 8080         # web dashboard
defense-kit monitor                       # quick scan + diff
defense-kit comply --framework cis        # compliance report
defense-kit schedule enable --interval 6h # auto-scan
defense-kit tools check                   # show available scanners/tools
```

## Architecture

- **Go binary** in `defense-kit-cli/` — single binary, all scanners
- **Docker** in `docker/` — isolated code/dependency scanning
- **Claude agents** in `.claude/` — AI copilot for recommendations

## Rules

- Scan mode is READ-ONLY
- Harden mode REQUIRES user approval
- Always generate rollback script before modifying
- Never break SSH or networking
