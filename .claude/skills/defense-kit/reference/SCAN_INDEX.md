# Scan Category Index

Master index of all 30 scan categories in defense-kit v2.

| # | Category | Group | What It Detects | External Tools | Severity Range |
|---|----------|-------|----------------|---------------|----------------|
| 1 | shell_rc | environment | .bashrc/.zshrc poisoning, pipe-to-shell, eval obfuscation | — | MEDIUM–CRITICAL |
| 2 | env_vars | environment | PATH hijacking, LD_PRELOAD, PROMPT_COMMAND exfiltration | — | MEDIUM–CRITICAL |
| 3 | ld_preload | environment | /etc/ld.so.preload entries, rogue library paths | — | HIGH–CRITICAL |
| 4 | pam | environment | Unauthorized PAM modules, auth bypass | — | HIGH–CRITICAL |
| 5 | cron | persistence | Malicious cron entries, pipe-to-shell in crontab | — | HIGH–CRITICAL |
| 6 | systemd | persistence | Rogue systemd units, drop-in overrides | — | HIGH–CRITICAL |
| 7 | scheduled | persistence | at jobs, anacron, systemd timers | — | MEDIUM–HIGH |
| 8 | processes | process | Reverse shells, crypto miners, suspicious daemons | — | HIGH–CRITICAL |
| 9 | memory | process | Deleted binaries in /proc, injected shared libs | — | HIGH–CRITICAL |
| 10 | clipboard | process | xinput sniffers, X11 keyloggers | — | HIGH–CRITICAL |
| 11 | file_integrity | filesystem | Unknown SUID/SGID binaries | aide | HIGH |
| 12 | filesystem | filesystem | Hidden files, world-writable dirs, /tmp abuse | — | MEDIUM–HIGH |
| 13 | timestomp | filesystem | mtime/ctime anomalies (anti-forensics) | — | HIGH |
| 14 | capabilities | filesystem | Elevated Linux capabilities | — | HIGH |
| 15 | swap | filesystem | Secrets in swap, credential-leaking core dumps | — | MEDIUM–HIGH |
| 16 | ports | network | Unusual listening ports | nmap | MEDIUM |
| 17 | connections | network | Outbound C2 connections | — | HIGH–CRITICAL |
| 18 | dns | network | Rogue resolvers, DNS exfiltration | — | MEDIUM–HIGH |
| 19 | firewall | network | Unexpected iptables/nftables rules | — | MEDIUM–HIGH |
| 20 | vpn | network | WireGuard/VPN misconfigs, rogue peers | — | MEDIUM–HIGH |
| 21 | ssh | auth | Weak sshd_config, unauthorized keys, brute force | ssh-audit | MEDIUM–CRITICAL |
| 22 | users | auth | UID 0 accounts, sudoers modifications | — | HIGH–CRITICAL |
| 23 | browser | auth | Saved passwords in plaintext, risky extensions | — | MEDIUM–HIGH |
| 24 | rootkit | system | Hidden kernel modules, /dev anomalies, proc hiding | rkhunter, chkrootkit | CRITICAL |
| 25 | boot | system | GRUB tampering, initramfs modification | — | CRITICAL |
| 26 | logs | system | Truncated logs, gaps, disabled logging | — | MEDIUM–HIGH |
| 27 | package_manager | system | Modified package files, unauthorized repos | debsums | HIGH |
| 28 | credentials | code | AWS keys, private keys, API tokens, passwords | gitleaks, trufflehog | MEDIUM–CRITICAL |
| 29 | supply_chain | code | CVEs in dependencies, tampered packages | trivy, grype | LOW–CRITICAL |
| 30 | containers | code | Dockerfile issues, privileged containers | hadolint, dockle | LOW–HIGH |
| 31 | git_hooks | code | Malicious pre-commit/post-checkout hooks | — | HIGH–CRITICAL |
