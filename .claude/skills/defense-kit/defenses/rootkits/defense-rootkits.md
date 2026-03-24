# Defense: Rootkits

## Threat

Kernel-level or userspace rootkits hide processes, files, and network connections from the OS.

## Detection

### defense-kit scanners
- `rootkit` — hidden kernel modules, /dev anomalies, process hiding
- `ld_preload` — /etc/ld.so.preload entries, rogue library paths
- `memory` — deleted binaries, injected shared libraries, TracerPid

### Manual verification
```bash
# Kernel modules
diff <(cat /proc/modules | awk '{print $1}' | sort) <(ls /sys/module/ | sort)
rkhunter --check --skip-keypress
chkrootkit

# LD_PRELOAD
cat /etc/ld.so.preload
echo $LD_PRELOAD
ls /etc/ld.so.conf.d/

# Hidden processes
ls /proc/*/exe 2>/dev/null | while read f; do readlink "$f" | grep "(deleted)" && echo "DELETED: $f"; done
```

## Response

1. **Do NOT reboot** — rootkit may not survive reboot, preserving evidence
2. **Document**: capture /proc/modules, lsmod, running processes
3. **Boot live USB**: scan filesystem offline with ClamAV/rkhunter
4. **Reinstall**: if LKM rootkit confirmed, OS reinstall is safest
5. **Rotate all credentials**: assume everything was captured

## Prevention

- Enable Secure Boot
- `echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf` — block unused modules
- AIDE file integrity monitoring: `aide --init && aide --check`
- `kernel.modules_disabled=1` in sysctl (after boot, prevents new modules)

## Quick Reference

```bash
defense-kit scan --category system         # rootkit + boot + logs
rkhunter --check --skip-keypress           # external tool
chkrootkit                                 # external tool
```
