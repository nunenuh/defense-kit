# Defense: Lateral Movement

## Threat

Attacker pivots from compromised host to other systems via SSH, credential reuse, or network scanning.

## Detection

### defense-kit scanners
- `ssh` — SSH config allowing forwarding/tunneling
- `connections` — outbound SSH from unexpected processes
- `processes` — network scanning tools (nmap run by attacker)
- `firewall` — packet forwarding enabled

### Manual verification
```bash
# SSH forwarding
grep -i "AllowTcpForwarding\|GatewayPorts\|PermitTunnel" /etc/ssh/sshd_config

# Active SSH sessions
who
w
last | head -20

# Outbound SSH
ss -tnp | grep ":22"

# Network scanning from this host
ps aux | grep -i "nmap\|masscan\|zmap"
```

## Response

1. **Isolate**: disconnect compromised host from network
2. **Reset credentials**: change passwords/keys on ALL hosts the compromised host could reach
3. **Check other hosts**: run `defense-kit scan` on every host in the network
4. **Block**: firewall rules to prevent further pivoting
5. **Audit**: SSH access logs on all connected hosts

## Prevention

- Disable SSH forwarding: `AllowTcpForwarding no`
- Unique SSH keys per host (not shared keys)
- Network segmentation: separate management from production
- MFA for SSH: `AuthenticationMethods publickey,keyboard-interactive`

## Quick Reference

```bash
defense-kit scan --category auth           # SSH config
defense-kit scan --category network        # connections + firewall
defense-kit harden --dry-run               # preview SSH hardening
```
