---
name: defense-kit
description: Defensive security toolkit for scanning, hardening, and monitoring your OS, code, repos, containers, and infrastructure. Scans for misconfigurations, hardens systems automatically, monitors for changes. Use for securing your own environment — laptops, servers, repos, dependencies.
---

Defensive security toolkit. Scan, harden, and monitor your environment.
Use when user wants to secure their system, audit code, harden configs, or monitor for threats.

## Modes

### `/defense-kit scan` — Scan Mode
Audit everything. Find misconfigurations, vulnerabilities, exposed secrets, weak configs.
No changes made — report only.

### `/defense-kit harden` — Harden Mode
Auto-fix what it can, suggest manual fixes for the rest.
Requires user approval before making any changes.

### `/defense-kit monitor` — Monitor Mode
Watch for changes. Alert on anomalies, new open ports, file modifications, unauthorized access.

### `/defense-kit comply` — Compliance Mode
Generate compliance report against frameworks (CIS Benchmarks, SOC2, OWASP).

## Tool Stack

| Category | Tools |
|----------|-------|
| OS Audit | lynis, osquery |
| Firewall | ufw, iptables |
| File Integrity | AIDE, osquery |
| Network | nmap (self-scan), ss, netstat |
| Code | semgrep, bandit, gitleaks |
| Dependencies | trivy, grype, npm audit, pip-audit |
| Containers | hadolint, trivy, dockle |
| Secrets | gitleaks, trufflehog, age |
| Git Hardening | pre-commit, gh api |
| SSH | ssh-audit |
| Monitoring | osquery, fail2ban, auditd |
| DNS | resolvectl, dns-over-https check |

## Scan Targets

| Target | What It Checks |
|--------|---------------|
| **OS** | CIS benchmarks, open ports, weak configs, disk encryption, auto-lock, firewall status |
| **Network** | Open ports (self-scan), DNS leaks, VPN status, listening services |
| **Code** | SAST (semgrep, bandit), secrets in code (gitleaks), hardcoded credentials |
| **Repos** | Branch protection, signed commits, secret scanning, dependabot status |
| **Dependencies** | Known CVEs (trivy, grype), outdated packages, license compliance |
| **Containers** | Dockerfile lint (hadolint), image vulns (trivy), runtime config (dockle) |
| **Secrets** | Git history (gitleaks, trufflehog), .env files, SSH keys, API keys |
| **SSH** | Key strength, config hardening, authorized_keys audit |

## Workflow

**Phase 1: Inventory**
1. Detect OS, architecture, installed software
2. List running services, open ports, network interfaces
3. Find code repos, Dockerfiles, config files
4. Catalog what needs scanning

**Phase 2: Scan**
1. Run OS audit (lynis)
2. Self-scan network (nmap localhost, ss -tlnp)
3. Scan code for secrets and vulnerabilities
4. Scan dependencies for CVEs
5. Check container security
6. Audit SSH configuration
7. Check firewall rules

**Phase 3: Report**
1. Aggregate findings by severity
2. Categorize: critical (fix now), high (fix soon), medium (plan fix), low (info)
3. Generate report (markdown, HTML, or DOCX)
4. Map to compliance framework if requested

**Phase 4: Harden (if requested)**
1. Present findings with proposed fixes
2. Get user approval for each change
3. Apply fixes (firewall rules, sysctl params, SSH config, etc.)
4. Verify fix worked
5. Log all changes made

**Phase 5: Monitor (if requested)**
1. Set up file integrity monitoring
2. Configure network connection tracking
3. Set up alert rules (new ports, file changes, login attempts)
4. Run as daemon or cron job

## Runtime Environment

**Docker container** (recommended) or **local** (for OS-level scans).

Some scans REQUIRE local access (not container):
- OS audit (lynis needs real OS, not container OS)
- Firewall status (host firewall, not container)
- Disk encryption check
- Service management

For these, run locally: `defense-kit scan --local`
For code/deps/containers/secrets, Docker works fine.

## Output Structure

```
/defense-kit/outputs/{scan-name}/
├── report/
│   ├── defense-report.md
│   ├── defense-report.html     # Optional
│   └── findings.json
├── scans/
│   ├── os-audit/               # lynis output
│   ├── network/                # nmap, ss output
│   ├── code/                   # semgrep, bandit output
│   ├── deps/                   # trivy, grype output
│   ├── containers/             # hadolint, dockle output
│   ├── secrets/                # gitleaks, trufflehog output
│   └── ssh/                    # ssh-audit output
└── hardening/
    ├── changes-applied.log     # What was changed
    └── rollback.sh             # Undo all changes
```

## Critical Rules

- **Scan mode is READ-ONLY** — never modify anything without explicit user approval
- **Harden mode requires approval** — present changes, wait for confirmation
- **Generate rollback script** — every hardening change must be reversible
- **Log everything** — all scans and changes logged
- **Local scans for OS-level** — container can't scan host OS
- **No destructive actions** — never delete files, stop critical services, or break connectivity
