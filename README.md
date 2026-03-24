# defense-kit

[![CI](https://github.com/nunenuh/defense-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/nunenuh/defense-kit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Defensive security toolkit for Linux. 42 scanners, 4 hardeners, local dashboard, threat intelligence, forensics timeline. Scan, harden, monitor, and comply — from your laptop to your servers.

## Install

```bash
curl -sSL https://get.nunenuh.me/defense-kit | bash
```

Skip external tools:
```bash
curl -sSL https://get.nunenuh.me/defense-kit | bash -s -- --no-tools
```

Or clone:
```bash
git clone https://github.com/nunenuh/defense-kit.git
cd defense-kit && ./install.sh
```

## Quick Start

```bash
defense-kit scan                          # full system audit (42 scanners)
defense-kit scan --profile workstation    # preset for laptops
defense-kit dashboard --port 8080 --open  # browser dashboard
defense-kit harden --dry-run              # preview security fixes
defense-kit schedule enable --interval 6h # auto-scan
defense-kit comply --framework cis        # CIS Benchmark report
```

## Commands

| Command | What It Does |
|---------|-------------|
| `scan` | Read-only audit across 42 scanners |
| `harden` | Fix issues with approval + rollback |
| `monitor` | Quick scan + diff against baseline |
| `dashboard` | Local web dashboard (SQLite + htmx) |
| `comply` | Map findings to CIS/SOC2/OWASP |
| `schedule` | Auto-scan via systemd timer or cron |
| `baseline` | Track changes over time |
| `tools check` | Show scanners + external tools |
| `report html` | Generate HTML report |
| `outputs` | Manage scan history |

## What It Scans

42 scanners across 10 groups:

| Group | Scanners | What It Detects |
|-------|----------|----------------|
| **environment** | shell_rc, env_vars, ld_preload, pam | RC poisoning, PATH hijacking, library injection |
| **persistence** | cron, systemd, scheduled, xdg_autostart | Malicious cron/services, backdoor timers, XDG autostart abuse |
| **process** | processes, memory, clipboard | Reverse shells, miners, keyloggers |
| **filesystem** | integrity, anomalies, timestomp, capabilities, swap, encryption | SUID abuse, anti-forensics, unencrypted disks |
| **network** | ports, connections, dns, firewall, vpn, threat_intel | C2 connections, DNS exfiltration, known-bad IPs |
| **auth** | ssh, users, browser | Weak SSH, UID 0 backdoors, saved passwords |
| **system** | rootkit, boot, logs, package_manager, sysctl, services, mac, updates, auditd | Rootkits, log tampering, missing patches |
| **code** | credentials, supply_chain, containers, git_hooks, docker_runtime | Leaked secrets, CVEs, malicious hooks |
| **forensics** | ebpf, webshell | eBPF backdoors, webshell indicators |

## What It Hardens

| Hardener | Fixes |
|----------|-------|
| **SSH** | PermitRootLogin, PasswordAuth, EmptyPasswords, MaxAuthTries |
| **OS** | 9 sysctl params (ip_forward, ASLR, SYN cookies, etc.) |
| **Firewall** | UFW setup with SSH safety |
| **Git** | Disable hooks, enable fsckobjects |

Every fix: requires approval, creates backup, generates rollback script.

## External Tools

Installed by default. Enhance detection when available, graceful fallback when not.

rkhunter, chkrootkit, lynis, ClamAV, gitleaks, trufflehog, trivy, grype, hadolint, dockle, ssh-audit, semgrep, bandit, nmap, aide, debsums

## Dashboard

```bash
defense-kit dashboard --port 8080 --open
```

Local-only web UI with:
- Security overview with severity cards
- Filterable findings table
- Scan history with trend charts
- Scanner + tool status
- Settings management
- Background auto-scanning

## Docker

```bash
make docker-build
TARGET_PATH=/path/to/code make docker-up
make docker-scan
```

## Structure

```
defense-kit/
├── defense-kit-cli/          # Go binary (all source code)
│   ├── cmd/defense-kit/      # CLI entry point
│   └── internal/             # Scanner, hardener, reporter, dashboard, etc.
├── docker/                   # Dockerfile + docker-compose
├── .claude/                  # Claude agents + skill definition
├── policies/                 # Security baseline (YAML)
├── tools/                    # REGISTRY.md + PIPELINES.md
├── specs/                    # Design specs + gap analysis
├── install.sh                # Local installer
├── install-remote.sh         # curl-pipe installer
└── Makefile                  # Build targets
```

## How It Differs From pentest-kit

| | pentest-kit | defense-kit |
|---|---|---|
| Purpose | Find vulns in **others** | Protect **yourself** |
| Mode | Offensive | Defensive |
| Output | Pentest report | Compliance report + auto-fix |
| Runs | Per engagement | Continuously / scheduled |

## Credits

Part of the [nunenuh](https://github.com/nunenuh) security toolkit family alongside [pentest-kit](https://github.com/nunenuh/pentest-kit).
