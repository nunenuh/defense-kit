# Defense: Persistence Mechanisms

## Threat

Attackers install backdoors that survive reboots: cron jobs, systemd services, shell RC files, at jobs, authorized SSH keys.

## Detection

### defense-kit scanners
- `cron` — malicious cron entries with curl/wget pipes, reverse shells
- `systemd` — rogue services, drop-in overrides, user-level persistence
- `scheduled` — at(1) jobs, anacron, systemd timers
- `shell_rc` — .bashrc/.zshrc poisoning, PROMPT_COMMAND exfiltration

### Manual verification
```bash
# Cron
crontab -l
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
cat /etc/crontab

# Systemd
systemctl list-units --type=service --state=running
ls ~/.config/systemd/user/
systemctl list-timers

# Shell RC
diff ~/.bashrc /etc/skel/.bashrc
grep -n "curl\|wget\|eval\|base64\|/dev/tcp" ~/.bashrc ~/.zshrc

# SSH keys
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/
```

## Response

1. **Identify**: run `defense-kit scan --category persistence`
2. **Remove**: delete malicious entry (cron, service, RC line, key)
3. **Verify**: rescan to confirm removal
4. **Audit**: check logs for when entry was added (`stat`, `journalctl`)
5. **Monitor**: `defense-kit schedule enable --interval 1h` temporarily

## Prevention

- `echo root > /etc/cron.allow` — restrict cron to root
- `chattr +i /etc/crontab` — make crontab immutable
- Monitor with auditd: `auditctl -w /etc/cron.d -p wa`
- Use `defense-kit harden --mode interactive` for SSH hardening

## Quick Reference

```bash
defense-kit scan --category persistence    # scan cron + systemd + scheduled
defense-kit scan --category environment    # scan shell RC files
defense-kit harden --dry-run               # preview fixes
```
