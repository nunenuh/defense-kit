# Defense: Log Tampering

## Threat

Attackers delete, truncate, or modify logs to hide evidence of compromise.

## Detection

### defense-kit scanners
- `logs` — missing/empty auth.log, timestamp gaps, brute force patterns, disabled logging
- `timestomp` — mtime/ctime anomalies on system files

### Manual verification
```bash
# Check log existence
ls -la /var/log/auth.log /var/log/syslog
stat /var/log/auth.log

# Check for gaps (look at timestamps)
awk '{print $1, $2, $3}' /var/log/auth.log | uniq -c | head -20

# Logging service
systemctl status rsyslog syslog-ng systemd-journald

# Journal integrity
journalctl --verify
```

## Response

1. **Restore**: check log backups, logrotate archives
2. **Enable remote logging**: forward to separate syslog server
3. **Check other hosts**: if logs deleted on one, check others in same network
4. **Timeline**: correlate with file timestamps, cron entries

## Prevention

- Remote syslog: forward to central server that attacker can't reach
- Immutable logs: `chattr +a /var/log/auth.log`
- auditd: `auditctl -w /var/log -p wa`
- Log rotation audit: verify logrotate.conf isn't modified

## Quick Reference

```bash
defense-kit scan --category system         # logs + timestomp
journalctl --verify                        # check journal integrity
systemctl status rsyslog                   # check logging service
```
