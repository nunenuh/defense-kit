# Gap 03: Missing Capabilities — Entire Areas Not Covered

**Priority:** HIGH
**Impact:** Blind spots that a competent attacker would exploit

## Problem

Beyond stub scanners and weak detections, there are entire capability areas that defense-kit doesn't address at all — not even as stubs.

---

## 1. No Threat Intelligence Integration

**What's missing:** No IOC (Indicator of Compromise) feeds, no known-bad IP lists, no malware hash databases.

**Why it matters:** Without threat intel, defense-kit can only detect *patterns* (regex) but not *known threats* (signatures). A process connecting to a known C2 server is just "an outbound connection" without an IP reputation database.

**What to build:**
- Embedded list of known C2 IP ranges (updated periodically)
- Hash-based malware detection (compare binary hashes against known-bad lists)
- Integration with AbuseIPDB or similar API for IP reputation
- YARA rule support for signature-based file scanning
- Optional ClamAV integration for virus signature matching (the tool exists but scanner doesn't use it natively)

---

## 2. No Forensics Timeline / Event Correlation

**What's missing:** Findings are flat lists with no temporal correlation. Can't tell if events are related.

**Why it matters:** An attack chain looks like: "SSH key added at 3:00am → cron job created at 3:01am → outbound connection at 3:02am." Without correlation, these are three separate findings instead of one attack narrative.

**What to build:**
- Timestamp collection on all findings (when was this created/modified?)
- Timeline view: sort all findings by timestamp
- Correlation engine: group findings within same time window
- Attack chain detection: known patterns like "persistence + C2 + exfiltration"
- Baseline timestamp comparison: "this was clean at last scan, changed since"

---

## 3. No File Integrity Database (Beyond SUID)

**What's missing:** No baseline hash database of system files. Can only detect SUID anomalies, not general file tampering.

**Why it matters:** If `/usr/bin/sudo` is replaced with a trojaned version (same permissions, same name), defense-kit won't detect it because it only checks SUID bit, not file content.

**What to build:**
- Generate hash database of critical system files on first run
- Compare hashes on subsequent runs
- Focus on: /usr/bin/*, /usr/sbin/*, /lib/*, /etc/ssh/*, /etc/pam.d/*
- Integration with AIDE for comprehensive file integrity monitoring
- Package-based verification: `dpkg --verify` or `rpm -Va`

---

## 4. No Kernel Security Posture Assessment

**What's missing:** No sysctl parameter checking, no kernel hardening assessment.

**Why it matters:** Insecure kernel parameters enable attacks:
- `net.ipv4.ip_forward = 1` → packet forwarding (pivot point)
- `kernel.sysrq = 1` → magic SysRq (reboot, sync, etc.)
- `kernel.randomize_va_space = 0` → ASLR disabled
- `kernel.dmesg_restrict = 0` → kernel info leak
- ICMP redirect acceptance → MITM

**What to build:**
- Read `/proc/sys/` parameters
- Compare against CIS Benchmark recommended values
- Flag insecure defaults
- Hardener: apply secure sysctl settings (the os.go hardener stub should do this)

---

## 5. No Service Enumeration

**What's missing:** No audit of running services, what's enabled at boot, what's listening.

**Why it matters:** Unnecessary services increase attack surface. A running `telnetd`, `rsh`, or `rpcbind` is a direct vulnerability.

**What to build:**
- `systemctl list-units --type=service --state=running`
- Flag legacy/insecure services: telnet, rsh, rlogin, rexec, xinetd
- Flag services not expected on this type of system
- Compare against minimal service baseline

---

## 6. No Audit Framework Integration

**What's missing:** No auditd rule checking, no audit log analysis.

**Why it matters:** auditd is Linux's built-in security event logging. Without it configured, there's no record of file access, privilege escalation, or system calls.

**What to build:**
- Check if auditd is running
- Verify audit rules cover: file access to /etc/passwd, /etc/shadow, privilege escalation (execve as root), module loading
- Parse audit logs for suspicious events
- Flag if auditd is not installed or not running

---

## 7. No Container Runtime Security

**What's missing:** `containers.go` only lints Dockerfiles. Doesn't inspect running containers.

**Why it matters:**
- `/var/run/docker.sock` world-readable = instant root
- Privileged containers = host escape
- Containers with host network/PID = visibility into host
- Mounted host filesystems in containers

**What to build:**
- Check Docker socket permissions
- `docker ps` → flag privileged containers, host network, dangerous mounts
- Check for `--cap-add=SYS_ADMIN`, `--security-opt=apparmor:unconfined`
- Flag containers running as root
- Check for Docker API exposed on network port

---

## 8. No Secrets in Process Memory

**What's missing:** No scanning of `/proc/*/maps` or `/proc/*/mem` for secrets.

**Why it matters:** Running processes often have credentials in memory — database passwords, API keys, tokens. Memory dumping is a common post-exploitation technique.

**What to build:**
- Scan `/proc/*/environ` for all processes (not just self)
- Flag environment variables containing common secret patterns across all processes
- Check for core dump settings that would leak secrets: `/proc/sys/kernel/core_pattern`
- Verify `fs.suid_dumpable = 0` (no core dumps for SUID programs)

---

## 9. No AppArmor/SELinux Status

**What's missing:** No mandatory access control (MAC) assessment.

**Why it matters:** AppArmor/SELinux prevent processes from accessing resources beyond their profile. Without MAC, a compromised service can read any file the service user owns.

**What to build:**
- Check if AppArmor is enabled: `aa-status`
- Check if SELinux is enforcing: `getenforce`
- Flag if MAC is disabled or permissive
- Flag if critical services lack profiles/policies

---

## 10. No Disk Encryption Verification

**What's missing:** No check for full-disk encryption.

**Why it matters:** Laptop stolen → all data exposed. Server with unencrypted drives → physical access = full compromise.

**What to build:**
- Check for LUKS: `lsblk -o NAME,FSTYPE,MOUNTPOINT` → look for crypto_LUKS
- Check for dm-crypt: `/dev/mapper/` entries
- Flag unencrypted partitions containing user data
- Check if swap is encrypted

---

## 11. No Automatic Update Status

**What's missing:** No check for pending security updates.

**Why it matters:** Known CVEs with public exploits are the most common attack vector. Unpatched systems are trivially compromised.

**What to build:**
- `apt list --upgradable 2>/dev/null | grep -i security`
- `unattended-upgrades` status check
- Flag if auto-updates are disabled
- Flag critical security updates pending
- Check last update time: `stat /var/cache/apt/pkgcache.bin`
