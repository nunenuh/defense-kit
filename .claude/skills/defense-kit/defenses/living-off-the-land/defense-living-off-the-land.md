# Defense: Living Off The Land (LOLBins)

## Threat

Attackers use legitimate system tools (curl, wget, python, perl, openssl, socat, ncat, ssh) for malicious purposes. No malware to detect — just normal binaries used abnormally.

## Common Linux LOLBins

| Binary | Malicious Use |
|--------|--------------|
| `curl` / `wget` | Download payloads, exfiltrate data |
| `python3` | Reverse shells, in-memory execution |
| `perl` | Reverse shells, one-liner backdoors |
| `openssl` | Encrypted reverse shell, file encryption |
| `socat` | Port forwarding, reverse shells |
| `ncat` / `nc` | Reverse shells, file transfer |
| `ssh` | Tunneling, pivoting, SOCKS proxy |
| `base64` | Encode/decode payloads to bypass detection |
| `dd` | Disk wiping, data exfiltration |
| `crontab` | Persistence |
| `at` | One-time persistence |
| `nsenter` | Container escape |
| `strace` / `ltrace` | Credential sniffing |
| `tcpdump` | Traffic capture |
| `xterm` | Reverse shell via X11 |

## Detection

### defense-kit scanners
- `processes` — detects reverse shells using common LOLBins
- `shell_rc` — detects curl/wget pipes in RC files
- `cron` — detects cron entries using LOLBins
- `connections` — detects outbound from unexpected processes

### Manual verification
```bash
# Outbound connections from LOLBins
for bin in curl wget python3 perl openssl socat ncat; do
    pids=$(pgrep -x "$bin" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo "=== $bin (PIDs: $pids) ==="
        for pid in $pids; do
            ss -tnp | grep "pid=$pid" 2>/dev/null
        done
    fi
done

# Python/Perl with suspicious imports
ps aux | grep -E "python.*import.*(socket|subprocess|os)" 
ps aux | grep -E "perl.*Socket"

# Base64 encoded commands
ps aux | grep "base64.*-d"
grep -rn "base64" /etc/cron* /var/spool/cron/ 2>/dev/null

# OpenSSL as reverse shell
ps aux | grep "openssl s_client"
```

## Response

1. **Kill process**: identify and terminate the LOLBin misuse
2. **Check persistence**: how is the LOLBin being invoked (cron, RC, service?)
3. **Block network**: firewall the destination
4. **Audit command history**: check `.bash_history` for attacker commands

## Prevention

```bash
# Restrict access to dangerous binaries for non-admin users
# (careful — some are needed for normal operation)
chmod 750 /usr/bin/ncat /usr/bin/socat 2>/dev/null

# Monitor LOLBin execution with auditd
for bin in ncat socat openssl strace ltrace tcpdump nsenter; do
    path=$(which "$bin" 2>/dev/null)
    [ -n "$path" ] && auditctl -w "$path" -p x -k lolbin_exec
done

# AppArmor profiles for web servers
# Restrict what processes web apps can spawn

# defense-kit detects the network side
defense-kit scan --category process
defense-kit scan --category network
```

## References
- [Linux Endpoint Security 2025 - Cynet](https://www.cynet.com/endpoint-security/linux-endpoint-security-what-you-need-to-know-in-2025/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Linux Hardening Guide - Madaidan](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
