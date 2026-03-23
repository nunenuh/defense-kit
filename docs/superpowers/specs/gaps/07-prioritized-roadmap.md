# Gap 07: Prioritized Roadmap

Implementation order based on: threat coverage impact, effort, and your specific threat model (AWS key leak via compromised server or vulnerable app).

---

## Tier 1: CRITICAL — Would Have Caught Your AWS Key Leak

These directly address the attack vectors from your incident.

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 1 | **Fill connections.go** — detect outbound C2, data exfiltration | Medium | Catches active compromise |
| 2 | **Add git history scanning to credentials.go** — find committed-then-removed secrets | Small | Catches exactly your AWS key scenario |
| 3 | **Fill users.go** — detect unauthorized UID 0, sudoers changes | Small | Catches privilege escalation |
| 4 | **Fill logs.go** — detect log tampering, brute force patterns | Medium | Catches evidence destruction |
| 5 | **Fill systemd.go** — detect rogue services and timers | Medium | Catches modern persistence |

**Estimated effort:** 2-3 sessions
**Detection improvement:** 60% → 80% coverage

---

## Tier 2: HIGH — Core Detection Gaps

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 6 | **Improve rootkit detection** — hash-based module verification, not name-matching | Medium | Catches real rootkits, not just tutorial ones |
| 7 | **Improve process detection** — add python/perl/php reverse shell patterns, process→socket mapping | Medium | Catches non-bash reverse shells |
| 8 | **Fill dns.go** — detect DNS exfiltration, rogue resolvers | Small | Catches DNS-based attacks |
| 9 | **Fill memory.go** — detect deleted binaries, injected libraries | Small | Catches runtime injection |
| 10 | **Fill git_hooks.go** — detect malicious hooks in cloned repos | Small | Prevents supply chain via git |
| 11 | **Fill firewall.go** — audit iptables/nftables rules | Small | Detects network exposure |
| 12 | **Fill capabilities.go** — detect elevated Linux capabilities | Small | Catches privilege escalation |
| 13 | **Implement OS hardener** — sysctl parameter fixes | Medium | First non-SSH hardener |

**Estimated effort:** 3-4 sessions
**Detection improvement:** 80% → 92% coverage

---

## Tier 3: MEDIUM — Complete the Picture

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 14 | **Fill anomalies.go** — hidden files, world-writable dirs, /tmp abuse | Small | Catches filesystem abuse |
| 15 | **Fill timestomp.go** — mtime/ctime anomaly detection | Small | Detects anti-forensics |
| 16 | **Fill swap.go** — secrets in swap, core dump config | Small | Prevents secret persistence |
| 17 | **Fill vpn.go** — WireGuard/VPN config audit | Small | Catches VPN misconfig |
| 18 | **Fill scheduled.go** — at(1) jobs, anacron | Small | Complete persistence coverage |
| 19 | **Fill clipboard.go** — xinput sniffers, X11 keyloggers | Small | Catches keyloggers |
| 20 | **Fill browser.go** — plaintext password stores | Medium | Catches credential theft |
| 21 | **Fill boot.go** — GRUB/initramfs verification | Medium | Catches boot tampering |
| 22 | **Implement firewall hardener** | Medium | Auto-fix network exposure |
| 23 | **Implement git hardener** | Small | Auto-fix hook attacks |
| 24 | **Improve SUID detection** — package verification instead of allowlist | Medium | Reduces false positives |

**Estimated effort:** 3-4 sessions
**Detection improvement:** 92% → 98% coverage

---

## Tier 4: POLISH — Production Grade

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 25 | **Build vulnerable test container** — integration test infrastructure | Medium | Testing confidence |
| 26 | **Add false positive testing** — run on clean system, suppress known-good | Medium | Usability |
| 27 | **Add structured logging** — zerolog/slog with levels | Small | Debugging/audit |
| 28 | **Add progress reporting** — real-time scanner progress | Small | UX |
| 29 | **Add scan profiles** — workstation/server/ci presets | Small | Usability |
| 30 | **Add threat intel** — known-bad IP list, YARA rules | Large | Detection depth |
| 31 | **Add kernel sysctl scanning** — new scanner | Medium | Kernel hardening |
| 32 | **Add service enumeration** — new scanner | Medium | Attack surface |
| 33 | **Add AppArmor/SELinux check** — new scanner | Small | MAC assessment |
| 34 | **Add disk encryption check** — new scanner | Small | Physical security |
| 35 | **Add auto-update check** — pending security patches | Small | Patch management |
| 36 | **Add CLI integration tests** — test all commands | Medium | Quality |
| 37 | **Add Docker runtime scanning** — running container audit | Medium | Container security |
| 38 | **Add audit framework check** — auditd rules verification | Medium | Compliance |

---

## Summary

| Tier | Tasks | Sessions | Coverage After |
|------|-------|----------|---------------|
| Current | — | — | 60% |
| Tier 1 (Critical) | 5 | 2-3 | 80% |
| Tier 2 (High) | 8 | 3-4 | 92% |
| Tier 3 (Medium) | 11 | 3-4 | 98% |
| Tier 4 (Polish) | 14 | 4-5 | 100% + production-grade |

**Total to complete everything:** ~12-16 sessions

**Recommendation:** Start with Tier 1. Items #1 (connections) and #2 (git history scanning) alone would have caught your AWS key leak.
