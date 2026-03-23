# Gap 01: Stub Scanners — 13 Scanners That Detect Nothing

**Priority:** CRITICAL
**Impact:** 42% of advertised scan categories are non-functional

## Problem

These scanners implement the `Scanner` interface but their `Scan()` method returns `nil, nil` — they generate zero findings regardless of what's on the system.

## Stub Inventory

### Network Group (4 stubs — entire group except ports)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| connections | `network/connections.go` | Outbound C2 connections, suspicious destinations, data exfiltration |
| dns | `network/dns.go` | Rogue DNS resolvers, DNS-over-HTTPS bypass, DNS exfiltration patterns |
| firewall | `network/firewall.go` | Unexpected iptables/nftables rules, permissive NAT, forwarding rules |
| vpn | `network/vpn.go` | WireGuard misconfigs, split tunnel leaks, rogue peers |

### Persistence Group (2 stubs)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| systemd | `persistence/systemd.go` | Rogue user/system services, drop-in overrides, generator scripts |
| scheduled | `persistence/scheduled.go` | at(1) jobs, anacron entries, systemd timers |

### Filesystem Group (4 stubs)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| anomalies | `filesystem/anomalies.go` | Hidden dotfiles in unusual places, world-writable dirs, /tmp abuse |
| timestomp | `filesystem/timestomp.go` | mtime/ctime inconsistencies (anti-forensics indicator) |
| capabilities | `filesystem/capabilities.go` | Binaries with cap_setuid, cap_net_raw, etc. |
| swap | `filesystem/swap.go` | Secrets persisted in swap, core dump configs leaking creds |

### Process Group (2 stubs)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| memory | `process/memory.go` | Processes running from deleted binaries, injected .so, /proc/*/maps anomalies |
| clipboard | `process/clipboard.go` | xinput sniffers, xdotool, xclip monitoring processes |

### Auth Group (2 stubs)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| users | `auth/users.go` | Unauthorized UID 0 accounts, sudoers modifications, recently created users |
| browser | `auth/browser.go` | Plaintext passwords in browser stores, risky extensions |

### System Group (2 stubs)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| boot | `system/boot.go` | GRUB config tampering, initramfs modifications, unsigned kernels |
| logs | `system/logs.go` | Truncated auth.log, gaps in journal, disabled logging services |

### Code Group (1 stub)

| Scanner | File | What It Should Detect |
|---------|------|----------------------|
| git_hooks | `code/githooks.go` | Malicious pre-commit, post-checkout, post-merge hooks in cloned repos |

## Implementation Requirements Per Stub

### connections.go — HIGHEST PRIORITY

```
Data sources:
- /proc/net/tcp, /proc/net/tcp6 (ESTABLISHED connections)
- /proc/*/fd → socket inodes → map to connections
- Known-bad IP lists (embedded or configurable)

Detection logic:
- Outbound connections to non-standard ports (not 80/443/53/22)
- Connections to known C2 IP ranges
- Process → connection mapping (which process opened which socket)
- High-frequency short-lived connections (beaconing pattern)
- Connections from unexpected processes (sshd connecting outbound)

Severity:
- Known C2 destination → CRITICAL
- Unexpected outbound from system process → HIGH
- Non-standard port outbound → MEDIUM
```

### systemd.go — HIGH PRIORITY

```
Data sources:
- /etc/systemd/system/*.service
- ~/.config/systemd/user/*.service
- /etc/systemd/system/*.timer
- /run/systemd/generator/*
- systemctl list-units --type=service --state=running

Detection logic:
- User-level services in ~/.config/systemd/user/ (unusual on servers)
- Services with ExecStart pointing to /tmp, /dev/shm, /var/tmp
- Services running as root with writable ExecStart paths
- Drop-in overrides that modify ExecStart
- Recently created unit files (mtime check)
- Services not from installed packages (cross-ref with dpkg -S)

Severity:
- ExecStart from /tmp or /dev/shm → CRITICAL
- User-level service with network access → HIGH
- Drop-in override modifying ExecStart → HIGH
- Recently created unknown service → MEDIUM
```

### users.go — HIGH PRIORITY

```
Data sources:
- /etc/passwd (UID 0 accounts, shell assignments)
- /etc/shadow (password age, locked accounts)
- /etc/sudoers, /etc/sudoers.d/*
- /etc/group (unusual group memberships)
- last, lastlog (recent logins)

Detection logic:
- Multiple UID 0 accounts (only root should be 0)
- Users with /bin/bash shell but no known purpose
- NOPASSWD entries in sudoers
- Users added to sudo/wheel/admin group recently
- Accounts with no password set
- Login from unusual source IPs (if lastlog available)

Severity:
- Non-root UID 0 account → CRITICAL
- NOPASSWD sudo for non-service accounts → HIGH
- User with shell but no home dir → MEDIUM
- Stale accounts with shell access → LOW
```

### logs.go — HIGH PRIORITY

```
Data sources:
- /var/log/auth.log (or /var/log/secure)
- /var/log/syslog
- journalctl --verify
- /etc/rsyslog.conf, /etc/syslog-ng/
- systemctl status rsyslog/syslog-ng

Detection logic:
- auth.log missing or empty → CRITICAL
- Gaps in log timestamps (>1 hour missing)
- Log files with mtime but 0 bytes (truncated)
- Logging service not running → HIGH
- Log rotation config modified recently
- Failed SSH login spikes (brute force indicator)
- su/sudo failures from unexpected users

Severity:
- Missing/empty auth.log → CRITICAL
- Logging service disabled → HIGH
- Timestamp gaps → HIGH
- Brute force pattern → MEDIUM
```

### dns.go

```
Data sources:
- /etc/resolv.conf
- resolvectl status (if systemd-resolved)
- /etc/systemd/resolved.conf
- Active DNS queries via /proc/net/udp (port 53)

Detection logic:
- Resolver pointing to non-standard IP (not ISP, not well-known public DNS)
- Multiple DNS resolvers (possible MITM)
- DNS-over-HTTPS configured to unknown endpoint
- Outbound UDP port 53 to non-resolver IPs (DNS exfiltration)

Severity:
- Unknown DNS resolver → HIGH
- DNS traffic to non-resolver → CRITICAL (exfiltration)
- DoH to unknown endpoint → MEDIUM
```

### memory.go

```
Data sources:
- /proc/*/exe → readlink (deleted binary detection)
- /proc/*/maps (injected shared libraries)
- /proc/*/status (TracerPid != 0 → being debugged)

Detection logic:
- Process exe symlink contains "(deleted)" → CRITICAL
- Shared libraries loaded from /tmp, /dev/shm → CRITICAL
- Process being traced by another process → HIGH
- Anonymous mapped regions with execute permission → MEDIUM

Severity:
- Deleted binary process → CRITICAL
- Library from /tmp → CRITICAL
- TracerPid != 0 → HIGH
```

### git_hooks.go

```
Data sources:
- Walk target paths for .git/hooks/ directories
- Check hook files: pre-commit, post-checkout, post-merge, pre-push

Detection logic:
- Any executable hook file in a cloned repo
- Hooks containing curl/wget/nc/base64/eval
- Hooks that download and execute
- Hooks not matching common frameworks (husky, pre-commit)

Severity:
- Hook with network calls → CRITICAL
- Hook with eval/exec → HIGH
- Any non-framework hook → MEDIUM (informational)
```

### firewall.go

```
Data sources:
- iptables -L -n (or iptables-save)
- nft list ruleset
- ufw status verbose

Detection logic:
- No firewall active → MEDIUM
- ACCEPT rules for unexpected ports
- FORWARD chain enabled (packet forwarding)
- NAT rules redirecting traffic
- Rules added by non-package sources (no comment/owner)

Severity:
- Forwarding enabled → HIGH
- Unexpected ACCEPT rules → MEDIUM
- NAT redirect → HIGH
- No firewall → MEDIUM
```

### capabilities.go

```
Data sources:
- getcap -r / (recursive capability scan)
- Or: walk /usr/bin, /usr/sbin and check xattr

Detection logic:
- cap_setuid on non-standard binaries → CRITICAL
- cap_net_raw on non-standard binaries → HIGH
- cap_net_admin → HIGH
- cap_sys_admin → CRITICAL
- Any capability on /tmp or /home binaries → CRITICAL

Severity:
- cap_setuid/cap_sys_admin → CRITICAL
- cap_net_raw/cap_net_admin → HIGH
- Other capabilities → MEDIUM
```

### Remaining stubs (anomalies, timestomp, swap, clipboard, browser, boot, scheduled, vpn)

See section-specific specs for detailed implementation requirements. Each follows the same pattern: data sources → detection logic → severity mapping.
