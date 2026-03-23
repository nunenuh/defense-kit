# Gap 04: Hardener Gaps — 3 of 4 Hardeners Are Empty

**Priority:** HIGH
**Impact:** Can only auto-fix SSH issues. Everything else is report-only.

## Problem

The hardener framework (engine, registry, rollback system) is solid. But only the SSH hardener has real logic. OS, firewall, and git hardeners have `CanFix() → false` and do nothing.

## Current State

| Hardener | CanFix | Fixes | Status |
|----------|--------|-------|--------|
| SSH | YES | PermitRootLogin, PasswordAuth, EmptyPasswords, MaxAuthTries | WORKING |
| OS | NO | — | EMPTY STUB |
| Firewall | NO | — | EMPTY STUB |
| Git | NO | — | EMPTY STUB |

## What Each Hardener Should Fix

### OS Hardener (`hardener/os.go`)

**sysctl hardening:**
```
net.ipv4.ip_forward = 0                    # disable packet forwarding
net.ipv4.conf.all.accept_redirects = 0     # reject ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0  # reject source routing
net.ipv4.tcp_syncookies = 1               # enable SYN flood protection
net.ipv4.icmp_echo_ignore_broadcasts = 1  # ignore broadcast pings
kernel.randomize_va_space = 2              # enable ASLR
kernel.sysrq = 0                           # disable magic SysRq
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1                  # restrict kernel message access
fs.suid_dumpable = 0                       # no core dumps for SUID
```

**Implementation:**
- CanFix: match findings from a future sysctl scanner
- Preview: show which parameters will change
- Apply: write to `/etc/sysctl.d/99-defense-kit.conf` then `sysctl --system`
- Verify: read back with `sysctl <param>`
- Rollback: remove the conf file, re-run `sysctl --system`

### Firewall Hardener (`hardener/firewall.go`)

**UFW hardening:**
```
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw enable
```

**Implementation:**
- CanFix: match findings from firewall scanner (no firewall active, permissive rules)
- Preview: show rules that will be added
- Apply: run ufw commands via exec.CommandContext
- Verify: `ufw status verbose`
- Rollback: `ufw disable` or remove specific rules
- CRITICAL: never lock out SSH. Always allow port 22 before enabling.

### Git Hardener (`hardener/git.go`)

**Git security hardening:**
```
git config --global core.hooksPath /dev/null     # disable all hooks (nuclear option)
# Or: install pre-commit framework with gitleaks
git config --global init.defaultBranch main
git config --global transfer.fsckobjects true    # verify objects on fetch
git config --global receive.fsckobjects true
git config --global fetch.fsckobjects true
```

**Implementation:**
- CanFix: match findings from git_hooks scanner
- Preview: show config changes
- Apply: run `git config --global`
- Verify: read back with `git config --global --get`
- Rollback: `git config --global --unset`

## Additional Hardeners Needed

### Cron Hardener (NEW)
- Remove malicious cron entries found by cron scanner
- Restrict cron access via `/etc/cron.allow`

### User Hardener (NEW)
- Lock suspicious accounts: `usermod -L <user>`
- Remove unauthorized UID 0: `usermod -u <newuid> <user>`
- Remove NOPASSWD from sudoers

### PAM Hardener (NEW)
- Remove unauthorized PAM modules
- Restore default PAM configs from package

### Systemd Hardener (NEW)
- Disable and remove rogue systemd services
- `systemctl disable --now <service>`

## Implementation Priority

1. **OS Hardener** — sysctl fixes are safe, well-understood, easily reversible
2. **Firewall Hardener** — critical for network exposure, but dangerous (can lock out SSH)
3. **Git Hardener** — prevents hook-based attacks
4. **Cron Hardener** — remove persistence
5. **User Hardener** — remove backdoor accounts
