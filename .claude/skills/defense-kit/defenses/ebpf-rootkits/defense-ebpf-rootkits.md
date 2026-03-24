# Defense: eBPF-Based Rootkits

## Threat

Modern rootkits use eBPF (extended Berkeley Packet Filter) to hook system calls without loading kernel modules. They bypass Secure Boot, are invisible to traditional LKM scanners (rkhunter, chkrootkit), and can hide processes, files, and network connections at the kernel level.

**Known malware:** BPFDoor (151+ variants in 2025), Symbiote, LinkPro, pamspy

## Why Traditional Detection Fails

- eBPF programs don't appear in `/proc/modules` or `lsmod`
- They bypass Secure Boot (no out-of-tree module loading needed)
- They intercept `getdents` to hide files, `read` to filter output
- They can filter network packets before userspace sees them
- Standard rootkit scanners (rkhunter, chkrootkit) are blind to eBPF

## Detection

### defense-kit scanners
- `rootkit` — checks /proc/modules vs /sys/module, but needs eBPF-specific checks
- `memory` — may detect injected eBPF programs via /proc/*/maps anomalies
- `connections` — may miss connections hidden by eBPF packet filters

### Manual verification
```bash
# List loaded eBPF programs (requires root)
bpftool prog list
bpftool prog list | grep -v "cgroup\|sk_filter"  # filter known-good

# Check for eBPF programs attached to tracepoints
bpftool perf list

# Check eBPF maps (rootkits store config here)
bpftool map list

# Check for BPFDoor specifically — listens on raw sockets
ss -0 | grep -i raw
cat /proc/net/raw

# Check /etc/ld.so.preload (LinkPro fallback)
cat /etc/ld.so.preload

# Kernel audit for bpf syscalls
ausearch -sc bpf 2>/dev/null | tail -20
```

## Response

1. **Don't trust userspace tools** — eBPF rootkits can filter their output
2. **Use bpftool from a trusted source** — copy from a known-clean system
3. **Detach malicious programs**: `bpftool prog detach id <ID> <attach_type>`
4. **Check for persistence**: look in `/etc/ld.so.preload`, systemd services, cron
5. **Kernel-level verification**: boot from live USB to inspect filesystem offline
6. **Consider reinstall** if BPFDoor/Symbiote confirmed

## Prevention

```bash
# Disable unprivileged eBPF (critical!)
sysctl kernel.unprivileged_bpf_disabled=1
echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-defense-kit.conf

# Enable BPF JIT hardening
sysctl net.core.bpf_jit_harden=2
echo "net.core.bpf_jit_harden=2" >> /etc/sysctl.d/99-defense-kit.conf

# Audit bpf syscalls
auditctl -a always,exit -F arch=b64 -S bpf -k ebpf_monitor

# Install LKRG (Linux Kernel Runtime Guard)
# Detects kernel integrity violations including eBPF abuse

# Runtime monitoring with Falco
# Falco can detect eBPF program loading in real-time
```

## Quick Reference

```bash
bpftool prog list                          # list all eBPF programs
bpftool prog show id <ID>                  # details of specific program
sysctl kernel.unprivileged_bpf_disabled    # check if restricted
defense-kit scan --category system         # rootkit scanner
```

## References
- [BPFDoor and Symbiote eBPF Rootkits](https://cyberpress.org/bpfdoor-and-symbiote-rootkits/)
- [LinkPro eBPF Rootkit Analysis - Synacktiv](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)
- [eBPF Backdoor Detection Framework](https://windshock.github.io/en/post/2025-04-29-ebpf-backdoor-detection-framework/)
