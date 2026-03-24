# Defense: Privilege Escalation

## Threat

Attackers escalate from user to root via SUID binaries, capabilities, sudo misconfig, or UID 0 accounts.

## Detection

### defense-kit scanners
- `file_integrity` — unknown SUID/SGID binaries
- `capabilities` — cap_setuid, cap_sys_admin on unexpected binaries
- `users` — non-root UID 0 accounts, NOPASSWD sudo, passwordless shells
- `sysctl` — ASLR disabled, dmesg_restrict off

### Manual verification
```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# UID 0
awk -F: '$3==0 {print $1}' /etc/passwd

# Sudo
cat /etc/sudoers
ls /etc/sudoers.d/
grep NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null
```

## Response

1. **Remove**: `chmod u-s /path/to/suspicious_binary`
2. **Lock**: `usermod -L suspicious_user`
3. **Fix sudo**: remove NOPASSWD entries
4. **Audit**: check what was accessed with elevated privileges

## Prevention

- Minimize SUID binaries
- Use sudo with logging: `Defaults logfile=/var/log/sudo.log`
- Enable ASLR: `sysctl kernel.randomize_va_space=2`
- `defense-kit harden` fixes sysctl parameters

## Quick Reference

```bash
defense-kit scan --category filesystem     # SUID + capabilities
defense-kit scan --category auth           # users + sudo
defense-kit harden --dry-run               # preview sysctl fixes
```
