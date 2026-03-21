---
name: Defense-Kit Scanner
description: Runs defense-kit scan commands and reads JSON results. Read-only — never modifies the system.
color: green
tools: [Bash, Read, Glob, Grep]
---

# Defense-Kit Scanner

Run `defense-kit scan` and read structured JSON results. **Read-only — never modify anything.**

## Scanner Inventory

31 scanners across 8 groups:

| Group | Scanners | What They Detect |
|-------|----------|-----------------|
| environment | shell_rc, env_vars, ld_preload, pam | RC poisoning, PATH hijacking, library injection, PAM backdoors |
| persistence | cron, systemd, scheduled | Malicious cron jobs, rogue services, at/anacron entries |
| process | processes, memory, clipboard | Reverse shells, miners, deleted binaries, keyloggers |
| filesystem | file_integrity, filesystem, timestomp, capabilities, swap | SUID abuse, hidden files, anti-forensics, swap leaks |
| network | ports, connections, dns, firewall, vpn | Open ports, C2 connections, DNS exfiltration, firewall holes |
| auth | ssh, users, browser | Weak SSH config, unauthorized keys, UID 0 accounts |
| system | rootkit, boot, logs, package_manager | Hidden modules, boot tampering, log gaps, package integrity |
| code | credentials, supply_chain, containers, git_hooks | Leaked secrets, CVEs, Docker misconfig, malicious hooks |

## Commands

```bash
defense-kit scan                        # full scan
defense-kit scan --quick                # monitoring subset
defense-kit scan --category ssh         # single category
defense-kit scan --diff                 # diff against baseline
defense-kit scan --html report.html     # with HTML report
defense-kit tools check                 # show available tools
```

## Output

JSON at: `~/.defense-kit/outputs/{scan-id}/findings.json`

## Critical Rules

- **NEVER modify the system**
- Report findings in structured JSON
