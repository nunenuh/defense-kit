---
name: defense-kit
description: Defensive security toolkit — scan, harden, monitor, and comply for Linux endpoints. Go binary with 31 scanners, 17 external tool integrations, AI copilot recommendations.
---

# Defense-Kit

Comprehensive defensive security toolkit for Linux laptops and servers.

## Architecture

```
User → Go binary (defense-kit) → ┬→ 31 native scanners (8 groups)
                                  ├→ 17 external tools (rkhunter, ClamAV, trivy...)
                                  ├→ Reports (terminal, JSON, HTML, alerts)
                                  └→ Claude copilot (AI recommendations)
```

- **Go binary on host** for OS/kernel/process/network scans
- **Docker container** for isolated code/dependency scanning
- **Claude `/loop`** or **systemd/cron** for continuous monitoring

## 4 Modes

| Command | Mode | Description |
|---------|------|-------------|
| `defense-kit scan` | Scan | Read-only audit across 30 categories |
| `defense-kit harden` | Harden | Detect → recommend → approve → fix → rollback |
| `defense-kit monitor` | Monitor | Quick scan + baseline diff |
| `defense-kit comply` | Comply | Map findings to CIS/SOC2/OWASP |

## 31 Scanners (8 Groups)

| Group | Scanners | Detects |
|-------|----------|---------|
| environment | shell_rc, env_vars, ld_preload, pam | RC poisoning, PATH hijacking, library injection, PAM backdoors |
| persistence | cron, systemd, scheduled | Malicious cron, rogue services, at jobs |
| process | processes, memory, clipboard | Reverse shells, miners, deleted binaries, keyloggers |
| filesystem | file_integrity, filesystem, timestomp, capabilities, swap | SUID abuse, hidden files, anti-forensics, swap leaks |
| network | ports, connections, dns, firewall, vpn | Open ports, C2 connections, DNS exfiltration, VPN misconfig |
| auth | ssh, users, browser | Weak SSH config, unauthorized keys, UID 0 accounts |
| system | rootkit, boot, logs, package_manager | Hidden modules, boot tampering, log gaps, package integrity |
| code | credentials, supply_chain, containers, git_hooks | Leaked secrets, CVEs, Docker misconfig, malicious hooks |

## External Tools (17)

rkhunter, chkrootkit, lynis, ClamAV, gitleaks, trufflehog, trivy, grype, hadolint, dockle, ssh-audit, semgrep, bandit, nmap, aide, debsums, ss

Scanners use external tools when available, fall back to native Go checks when not.

## CLI Reference

```bash
# Scanning
defense-kit scan                              # full scan
defense-kit scan --quick                      # fast subset
defense-kit scan --category rootkit           # single category
defense-kit scan --diff                       # compare to baseline
defense-kit scan --html report.html           # HTML report
defense-kit scan --alert                      # send alerts

# Hardening
defense-kit harden --dry-run                  # preview fixes
defense-kit harden --mode interactive         # fix with approval

# Monitoring
defense-kit monitor                           # quick scan + diff
defense-kit schedule enable --interval 6h     # systemd/cron
defense-kit schedule status

# Compliance
defense-kit comply --framework cis

# Management
defense-kit baseline update                   # set baseline
defense-kit baseline diff                     # show changes
defense-kit tools check                       # show available tools
defense-kit report html report.html           # regenerate report
```

## Output

- Terminal: colored output with severity badges
- JSON: `~/.defense-kit/outputs/{scan-id}/findings.json`
- HTML: static dashboard (no JS, XSS-safe)
- Alerts: Slack webhook, email SMTP, generic webhook (HMAC-SHA256)

## Severity Classification

| Severity | Example | Action |
|----------|---------|--------|
| CRITICAL | Reverse shell, rootkit, leaked AWS key | Immediate alert |
| HIGH | Unknown SUID, unauthorized SSH key | Alert + recommend fix |
| MEDIUM | Package CVE, weak SSH config | Report + suggest |
| LOW | Missing best practice | Log only |

## Critical Rules

1. **Scan mode is read-only** — never modifies the system
2. **Harden requires approval** — every change needs consent
3. **Always rollback** — every fix generates reversible script
4. **No shell interpretation** — all commands use explicit argv
5. **Least privilege** — scan as user, sudo only when needed
6. **Never break SSH/networking**
