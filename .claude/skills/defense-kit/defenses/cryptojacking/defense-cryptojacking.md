# Defense: Cryptojacking

## Threat

Attackers install cryptocurrency miners (XMRig, cpuminer) on compromised servers. Often enters via SSH brute force, then persists via cron and authorized_keys.

**Known campaigns:** Outlaw/Hezb (SSH brute force → XMRig), TeamTNT, Kinsing

## Attack Pattern

1. Brute force SSH (weak passwords)
2. Drop SSH key in `~/.ssh/authorized_keys` for persistence
3. Download miner from C2 (often via `curl | bash`)
4. Hide via process renaming, cron @reboot persistence
5. Kill competing miners on the same host
6. Spread to other hosts via SSH with stolen keys

## Detection

### defense-kit scanners
- `processes` — detects xmrig, cpuminer, stratum+tcp connections
- `connections` — detects mining pool connections (stratum protocol)
- `cron` — detects persistence entries
- `ssh` — detects unauthorized authorized_keys
- `logs` — detects brute force patterns (Failed password)

### Manual verification
```bash
# High CPU processes
top -bn1 | head -20
ps aux --sort=-%cpu | head -10

# Known miner processes
ps aux | grep -iE "xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|stratum"

# Mining pool connections
ss -tnp | grep -E ":3333|:4444|:5555|:8888|:14433"
ss -tnp | grep "stratum"

# Check for miner persistence
grep -r "xmrig\|minerd\|stratum" /etc/cron* /var/spool/cron/ 2>/dev/null
grep -r "curl.*\|.*bash\|wget.*\|.*sh" /etc/cron* 2>/dev/null

# Unauthorized SSH keys
for user in /home/*/; do
    echo "=== $user ===" 
    wc -l "${user}.ssh/authorized_keys" 2>/dev/null
done
```

## Response

1. **Kill miner**: `pkill -9 -f xmrig` (they respawn — check cron first)
2. **Remove persistence**: clean cron entries, remove unauthorized SSH keys
3. **Block pool IPs**: `ufw deny out to <pool_ip>`
4. **Change SSH passwords**: or better, disable password auth entirely
5. **Check for lateral movement**: miners often spread via SSH

## Prevention

```bash
# Disable SSH password auth (most important!)
defense-kit harden --mode interactive  # fixes SSH config

# Install fail2ban
apt install fail2ban
systemctl enable fail2ban

# Block common mining ports outbound
ufw deny out 3333
ufw deny out 4444
ufw deny out 14433

# Limit SSH access
echo "AllowUsers youruser" >> /etc/ssh/sshd_config

# Monitor CPU usage
# Alert if any process >80% CPU for >5 minutes
```

## Quick Reference

```bash
defense-kit scan --category process        # detect miners
defense-kit scan --category persistence    # detect cron persistence
defense-kit scan --category auth           # detect SSH key injection
defense-kit harden --dry-run               # preview SSH hardening
```

## References
- [Outlaw SSH Brute Force Cryptojacking](https://thehackernews.com/2025/04/outlaw-group-uses-ssh-brute-force-to.html)
- [Outlaw Linux Malware Analysis - Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)
