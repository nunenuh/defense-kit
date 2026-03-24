# Defense: Network Attacks

## Threat

C2 connections, DNS exfiltration, exposed ports, firewall holes, rogue DNS resolvers.

## Detection

### defense-kit scanners
- `connections` — outbound C2, suspicious ports (4444, 1337), process mapping
- `dns` — rogue resolvers, DNS-over-HTTPS to unknown endpoints
- `ports` — unusual listening ports with process identification
- `firewall` — missing firewall, ip_forward enabled, permissive rules
- `threat_intel` — connections to known-bad IPs
- `vpn` — WireGuard/VPN misconfig, rogue peers

### Manual verification
```bash
# Active connections
ss -tnp | grep ESTAB
netstat -tnp 2>/dev/null

# DNS
cat /etc/resolv.conf
resolvectl status 2>/dev/null

# Listening ports
ss -tlnp

# Firewall
ufw status verbose
iptables -L -n
```

## Response

1. **Kill**: `kill -9 <PID>` for C2 process
2. **Block**: `ufw deny out to <C2_IP>`
3. **Capture**: `tcpdump -i any host <IP> -w capture.pcap`
4. **Trace**: identify how the connection was established
5. **Scan**: `defense-kit scan --category network`

## Prevention

- `defense-kit harden` enables UFW with deny-incoming
- Use DNS-over-TLS: configure systemd-resolved
- Block outbound to known-bad ranges
- Network segmentation between services

## Quick Reference

```bash
defense-kit scan --category network        # all network scanners
ss -tnp | grep -v "127.0.0.1\|::1"       # non-local connections
ufw enable && ufw default deny incoming   # basic firewall
```
