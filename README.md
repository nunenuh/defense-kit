# defense-kit

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Defensive security toolkit for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Scan, harden, and monitor your OS, code, repos, and infrastructure.

## Install

```bash
curl -sSL https://get.nunenuh.me/defense-kit | bash
```

Or clone:
```bash
git clone https://github.com/nunenuh/defense-kit.git
cd defense-kit
./install.sh
```

## Modes

| Mode | Command | What It Does |
|------|---------|-------------|
| **Scan** | `/defense-kit scan` | Audit everything, report findings (read-only) |
| **Harden** | `/defense-kit harden` | Scan + auto-fix with approval + rollback script |
| **Monitor** | `/defense-kit monitor` | Watch for changes, alert on anomalies |
| **Comply** | `/defense-kit comply` | Map findings to CIS/SOC2/OWASP frameworks |

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/nunenuh/defense-kit.git
cd defense-kit

docker compose build

# Scan your code
TARGET_PATH=/path/to/your/code docker compose up -d
docker compose exec defense-kit bash

# Quick scan
bash tools/scripts/quick-scan.sh /defense-kit/target/
```

### Local (for OS-level scans)

```bash
# Some scans need local access (OS audit, firewall, disk encryption)
./install.sh --local
/defense-kit scan --local
```

## What It Scans

| Target | Tools | Checks |
|--------|-------|--------|
| OS | lynis, osquery | CIS benchmarks, weak configs, disk encryption |
| Network | nmap, ss | Open ports, listening services, firewall rules |
| Code | semgrep, bandit | SAST vulnerabilities, insecure patterns |
| Secrets | gitleaks, trufflehog | Git history, .env files, API keys, private keys |
| Dependencies | trivy, grype, pip-audit | Known CVEs, outdated packages |
| Containers | hadolint, dockle, trivy | Dockerfile lint, image vulns, best practices |
| SSH | ssh-audit | Key strength, config hardening |
| Git | gh api | Branch protection, signed commits |

## What It Hardens

| Target | Actions |
|--------|---------|
| OS | sysctl params, core dump disable, auto-updates |
| Firewall | ufw enable, deny incoming, allow SSH |
| SSH | Disable root login, disable password auth, limit attempts |
| Git | Pre-commit hooks (gitleaks), branch protection, commit signing |
| Docker | Non-root user, healthcheck, pinned versions |

Every hardening change:
- Requires your approval
- Creates a backup
- Generates a rollback script

## Structure

```
defense-kit/
├── .claude/
│   ├── skills/defense-kit/SKILL.md
│   └── agents/
│       ├── orchestrator.md     # Coordinates scan/harden/monitor
│       ├── scanner.md          # Read-only scanning
│       └── hardener.md         # Fix with approval + rollback
├── scanners/                   # Scanner configs and scripts
├── hardeners/                  # Hardening playbooks
├── monitors/                   # Monitoring configs
├── policies/
│   └── baseline.yml            # Your security baseline
├── tools/scripts/
│   └── quick-scan.sh           # One-command full scan
├── Dockerfile                  # Kali-based container
└── docker-compose.yml
```

## How It Differs From pentest-kit

| | pentest-kit | defense-kit |
|---|---|---|
| Purpose | Find vulns in **others** | Protect **yourself** |
| Target | External apps/systems | Your own laptop/code/infra |
| Mode | Offensive | Defensive |
| Output | Pentest report | Compliance report + auto-fix |
| Runs | Per engagement | Continuously / scheduled |

## Credits

Part of the [nunenuh](https://github.com/nunenuh) security toolkit family alongside [pentest-kit](https://github.com/nunenuh/pentest-kit).
