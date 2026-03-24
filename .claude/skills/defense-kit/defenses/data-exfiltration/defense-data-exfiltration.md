# Defense: Data Exfiltration

## Threat

Data stolen via DNS tunneling, HTTP uploads, encrypted channels, or local media.

## Detection

### defense-kit scanners
- `connections` — outbound to non-standard ports, high-frequency beaconing
- `dns` — DNS exfiltration patterns, unusual resolver
- `threat_intel` — connections to known C2/exfiltration endpoints
- `swap` — credentials persisted in swap/core dumps

### Manual verification
```bash
# Large outbound transfers
ss -tnp | awk '{print $5}' | sort | uniq -c | sort -rn | head

# DNS queries (if tcpdump available)
tcpdump -i any port 53 -c 100 2>/dev/null

# Unusual DNS traffic volume
cat /proc/net/udp | wc -l

# Swap secrets
strings /dev/sda2 2>/dev/null | grep -i "password\|secret\|AKIA" | head
```

## Response

1. **Block channel**: firewall rule to block destination IP/port
2. **Identify scope**: what data was accessible to the compromised process
3. **Capture traffic**: `tcpdump -i any host <IP> -w evidence.pcap`
4. **Notify**: data breach notification if PII involved
5. **Rotate**: all credentials the exfiltration target could access

## Prevention

- Egress filtering: block unnecessary outbound ports
- DNS monitoring: use DNS-over-TLS, monitor query volume
- DLP: prevent large file transfers to unknown destinations
- Encrypt swap: `cryptsetup` for swap partition
- Core dump restriction: `sysctl fs.suid_dumpable=0`

## Quick Reference

```bash
defense-kit scan --category network        # connections + dns + threat_intel
defense-kit scan --category filesystem     # swap secrets
tcpdump -i any -c 1000 -w /tmp/capture.pcap  # capture traffic
```
