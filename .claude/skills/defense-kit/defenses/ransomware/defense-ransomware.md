# Defense: Linux Ransomware

## Threat

Ransomware targeting Linux servers encrypts files, databases, and VM disks. Often targets ESXi, NAS, and web servers. Entry via SSH brute force, web application exploit, or compromised credentials.

**Known families:** LockBit Linux, BlackCat/ALPHV, Royal, Akira, ESXiArgs

## Attack Pattern

1. Initial access via SSH, web exploit, or stolen credentials
2. Reconnaissance: identify valuable data, databases, VM storage
3. Disable backups and security tools
4. Encrypt files (often using `openssl enc` or embedded crypto)
5. Drop ransom note
6. Sometimes exfiltrate data first (double extortion)

## Detection

### defense-kit scanners
- `processes` — mass file operations, openssl enc processes
- `connections` — C2 communication before encryption
- `logs` — brute force indicators
- `file_integrity` — mass file changes (AIDE)

### Manual verification
```bash
# Check for mass file changes
find / -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" 2>/dev/null | head

# Ransom notes
find / -name "README*" -o -name "DECRYPT*" -o -name "RECOVER*" 2>/dev/null | head

# High disk I/O (encryption in progress)
iotop -b -n 3 2>/dev/null | head -20

# Suspicious openssl usage
ps aux | grep "openssl enc"

# Check backup integrity
ls -la /backup/ 2>/dev/null
```

## Response

1. **ISOLATE IMMEDIATELY**: disconnect from network to stop spread
2. **Don't reboot**: encryption process may still be running, killing it saves remaining files
3. **Preserve evidence**: snapshot/image the disk before recovery
4. **Restore from backup**: if backups exist and are clean
5. **Report**: law enforcement, CISA, your security team
6. **Do NOT pay**: no guarantee of decryption

## Prevention

```bash
# Immutable backups (most important!)
# Use backup solution with write-once-read-many (WORM)

# Disable SSH password auth
defense-kit harden --mode interactive

# Enable firewall
defense-kit harden --mode interactive  # enables UFW

# File system snapshots
# btrfs: btrfs subvolume snapshot / /snapshots/$(date +%Y%m%d)
# ZFS: zfs snapshot pool/data@$(date +%Y%m%d)

# Limit file permissions
# Web apps should not be able to write outside their directory

# Monitor with defense-kit
defense-kit schedule enable --interval 1h  # detect early
```

## References
- [Linux Ransomware Analysis - Cynet](https://www.cynet.com/ransomware/linux-ransomware-attack-anatomy-examples-and-protection/)
- [DripDropper Cloud Malware - Red Canary](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
