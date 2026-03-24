# Hardening Guide

## Approval Flow

```
Scan → Find fixable issues → Preview (dry-run) → Approve → Backup → Apply → Verify → Rollback script
```

## SSH Hardener

| Directive | Before | After |
|-----------|--------|-------|
| PermitRootLogin | yes | no |
| PasswordAuthentication | yes | no |
| PermitEmptyPasswords | yes | no |
| MaxAuthTries | 6+ | 3 |

Rollback: `cp ~/.defense-kit/backup-{ts}-sshd_config /etc/ssh/sshd_config && systemctl restart sshd`

## OS Hardener (sysctl)

| Parameter | Secure Value | Purpose |
|-----------|-------------|---------|
| net.ipv4.ip_forward | 0 | Disable forwarding |
| kernel.randomize_va_space | 2 | Enable ASLR |
| kernel.sysrq | 0 | Disable SysRq |
| kernel.dmesg_restrict | 1 | Restrict kernel logs |
| fs.suid_dumpable | 0 | No SUID core dumps |
| net.ipv4.tcp_syncookies | 1 | SYN flood protection |
| net.ipv4.conf.all.accept_redirects | 0 | Block ICMP redirects |
| net.ipv4.conf.all.send_redirects | 0 | Don't send redirects |
| net.ipv4.conf.all.accept_source_route | 0 | Block source routing |

Rollback: `rm /etc/sysctl.d/99-defense-kit.conf && sysctl --system`

## Firewall Hardener

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'   # ALWAYS first!
ufw --force enable
```

Rollback: `ufw disable`

## Git Hardener

```bash
git config --global core.hooksPath /dev/null
git config --global transfer.fsckobjects true
```

Rollback: `git config --global --unset core.hooksPath`

## Commands

```bash
defense-kit harden --dry-run              # preview
defense-kit harden --mode interactive     # approve each
defense-kit harden --mode auto-low        # auto-fix LOW/MEDIUM
```
