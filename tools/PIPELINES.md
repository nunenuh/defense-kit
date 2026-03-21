# Scan Pipelines

Defense-kit organises its scanners into named pipelines that group categories for different
operational scenarios. Each pipeline is a curated subset of the 30+ available scan categories,
tuned for a specific trade-off between coverage and speed.

Pipelines are specified with `--pipeline <name>` (or via the config file under `pipelines:`).
Individual categories can be appended (`--also <category>`) or excluded (`--skip <category>`)
at runtime without modifying the pipeline definition.

---

## Pipeline Overview

| Pipeline | Categories | External Tools | Typical Duration |
|----------|-----------|----------------|-----------------|
| `full_scan` | All 30 categories | All available tools preferred | 2–5 minutes |
| `quick_monitor` | 6 categories | Lightweight tools only | 10–30 seconds |
| `incident_response` | 8 targeted categories | All available tools, max urgency | 30–90 seconds |

---

## `full_scan`

**Purpose:** Complete security audit of the host. Run manually before a release, after a
suspicious event, or as a scheduled nightly job. Read-only — no changes are made.

**Parallelism:** Maximum (all CPU cores). External tools run concurrently where their output
is independent.

**Tool preference:** External tools are preferred over native Go checks when installed.
If an external tool is unavailable the scanner falls back to its native implementation
automatically.

### Categories (all 30)

| Category | Scanner Name(s) | External Tools Used |
|----------|----------------|---------------------|
| Rootkits | `rootkit` | rkhunter, chkrootkit |
| Malware | _(planned)_ | clamscan |
| Credentials / secrets | `credentials` | gitleaks, trufflehog |
| Supply chain / CVEs | `supply_chain` | trivy, grype |
| Container security | `containers` | hadolint, dockle |
| SSH configuration | `ssh` | ssh-audit |
| Code security | _(planned)_ | semgrep, bandit |
| Package integrity | `package_manager` | debsums |
| System audit | _(planned)_ | lynis |
| Network ports | `ports` | _(planned: nmap)_ |
| Network connections | `connections` | _(planned: ss)_ |
| DNS | `dns` | — |
| Firewall | `firewall` | — |
| VPN | `vpn` | — |
| File integrity | `file_integrity` | _(planned: aide)_ |
| Filesystem anomalies | `filesystem` | — |
| Timestomp detection | `timestomp` | — |
| Capabilities | `capabilities` | — |
| Swap analysis | `swap` | — |
| Processes | `processes` | — |
| Memory | `memory` | — |
| Clipboard | `clipboard` | — |
| Shell RC poisoning | `shell_rc` | — |
| Environment variables | `env_vars` | — |
| LD_PRELOAD hijacking | `ld_preload` | — |
| PAM configuration | `pam` | — |
| Systemd injection | `systemd` | — |
| Scheduled tasks / cron | `cron`, `scheduled` | — |
| Boot security | `boot` | — |
| Users / auth | `users` | — |
| Browser security | `browser` | — |
| Git hooks | `git_hooks` | — |
| Logs | `logs` | — |

### Typical Run

```bash
defense-kit scan --pipeline full_scan
```

Or equivalently (default when no pipeline is specified):

```bash
defense-kit scan
```

### Duration Breakdown

| Phase | Time |
|-------|------|
| Tool discovery + preflight | ~2 s |
| Native Go scanners (parallel) | ~10–30 s |
| rkhunter (signature database) | ~30–90 s |
| ClamAV full filesystem scan | ~1–3 min |
| trivy filesystem scan | ~20–60 s |
| Total | **2–5 min** |

ClamAV dominates the wall-clock time on large filesystems. Use `--skip malware` to omit it
for faster runs when antivirus is handled by another layer.

---

## `quick_monitor`

**Purpose:** Lightweight periodic scan designed for continuous monitoring via the Claude `/loop`
command at a 5-minute interval. Focuses on the categories most likely to show active compromise
indicators. Deliberately excludes slow external tools.

**Parallelism:** Full.

**Tool preference:** Only fast external tools (sub-second to a few seconds). Heavy tools
(ClamAV, trivy full-filesystem, rkhunter) are excluded from this pipeline.

### Categories (6)

| Category | Scanner Name | External Tools | Rationale |
|----------|-------------|----------------|-----------|
| Process anomalies | `processes` | — | Catch reverse shells and crypto-miners in real time |
| Network connections | `connections` | _(ss planned)_ | Detect C2 beacons and unexpected outbound connections |
| File integrity | `file_integrity` | — | Detect modifications to critical system files |
| Persistence | `cron`, `scheduled`, `systemd` | — | Catch newly added cron jobs or systemd units |
| SSH configuration | `ssh` | — (no ssh-audit; static config check only) | Detect new authorized_keys entries |
| Shell RC poisoning | `shell_rc` | — | Detect modifications to `.bashrc`, `.zshrc`, `.profile` |

### Monitoring with `/loop`

The `quick_monitor` pipeline is optimised for use with Claude's `/loop` built-in:

```
/loop "Run defense-kit scan --pipeline quick_monitor --format json and summarise any new findings compared to the previous run. Alert me immediately if severity is CRITICAL or HIGH."
```

Suggested interval: `5m`. Claude will re-run the scan every 5 minutes and diff findings.

### What is excluded and why

| Excluded | Reason |
|----------|--------|
| ClamAV (`clamscan`) | Full filesystem scan takes 1–3 minutes |
| rkhunter | Signature database check takes 30–90 seconds |
| trivy / grype | Dependency CVE scan takes 20–60 seconds |
| semgrep / bandit | Static code analysis not relevant for live monitoring |
| lynis | System audit report does not change between runs |
| DNS, VPN, firewall | Change rarely; included in `full_scan` |

### Typical Run

```bash
defense-kit scan --pipeline quick_monitor
```

With explicit interval via Claude loop:

```bash
# Triggered by Claude /loop every 5 minutes
defense-kit scan --pipeline quick_monitor --format json --output /tmp/defense-kit-monitor.json
```

### Duration Breakdown

| Phase | Time |
|-------|------|
| processes | ~1–2 s |
| connections | ~1 s |
| file_integrity | ~2–5 s |
| persistence (cron + systemd) | ~1–2 s |
| ssh (config check only) | ~1 s |
| shell_rc | ~1 s |
| Total | **~10–30 s** |

---

## `incident_response`

**Purpose:** Targeted scan for investigating a suspected active compromise. Covers the categories
most commonly involved in intrusions: rootkit installation, reverse shells, C2 communication,
credential theft, persistence mechanisms, and lateral movement preparation.

**Parallelism:** Full, with elevated priority. All available tools run immediately without
waiting for slower categories that are not included.

**Urgency:** All findings are reported immediately as they are discovered, rather than
aggregating at the end. Use `--stream` to enable real-time output.

**External tools:** All available tools are used for maximum detection confidence. No tool is
excluded for speed reasons — accuracy is the priority.

### Categories (8)

| Category | Scanner Name(s) | External Tools | What It Detects |
|----------|----------------|----------------|-----------------|
| Rootkits | `rootkit` | rkhunter, chkrootkit | Hidden processes, kernel module injection, suspicious /dev files |
| Processes | `processes` | — | Reverse shells (`bash -i`, `nc`, `python -c`), crypto-miners, process hollowing indicators |
| Network / C2 | `connections`, `ports` | _(nmap planned)_ | Outbound connections to non-standard ports, listening backdoors, C2 beacon patterns |
| Credentials | `credentials` | gitleaks, trufflehog | Stolen or leaked keys, tokens, and passwords on disk or in git history |
| Persistence | `cron`, `scheduled`, `systemd` | — | Unauthorized cron jobs, systemd units, at-jobs added by the attacker |
| SSH | `ssh` | ssh-audit | Unauthorized authorized_keys entries, weakened sshd_config, backdoor keys |
| Shell RC | `shell_rc` | — | RC file poisoning (export PATH manipulation, alias hijacking, reverse shell stagers) |
| Environment | `env_vars` | — | LD_PRELOAD injection, PATH hijacking, malicious environment variables |

### Typical Run

```bash
defense-kit scan --pipeline incident_response --stream
```

With AI correlation (recommended during active incident):

```bash
defense-kit scan --pipeline incident_response --stream --copilot
```

The `--copilot` flag enables the Claude hardener agent to correlate findings across categories
in real time and suggest immediate containment actions.

### Interpreting Results

During incident response, treat all HIGH and CRITICAL findings as confirmed indicators of
compromise until proven otherwise. Do not wait for the full scan to complete before beginning
containment — use `--stream` to act on findings as they appear.

Suggested triage order:
1. CRITICAL findings in `rootkit` — system may be fully compromised; consider isolating the host
2. CRITICAL findings in `credentials` — rotate exposed secrets immediately, before any other action
3. HIGH findings in `processes` — kill suspicious processes and capture forensic artefacts first
4. HIGH findings in `ssh` — revoke unauthorized keys and disable password auth
5. HIGH/MEDIUM findings in `persistence` — remove attacker persistence before rebooting
6. Remaining findings — remediate with `defense-kit harden` after containment

### Duration Breakdown

| Phase | Time |
|-------|------|
| processes + connections (parallel) | ~2–5 s |
| rootkit (native only, no full rkhunter) | ~5–10 s |
| credentials (gitleaks fast mode) | ~5–20 s |
| ssh + shell_rc + env_vars (parallel) | ~2–5 s |
| persistence (cron + systemd) | ~1–2 s |
| rkhunter (if installed) | ~30–60 s |
| Total | **~30–90 s** |

> Note: rkhunter runs in the background and its findings stream in as they are produced.
> The incident_response pipeline does not block on rkhunter completion — initial findings
> from all other categories are available within the first 30 seconds.

---

## Defining Custom Pipelines

Custom pipelines can be defined in the defense-kit config file (`~/.config/defense-kit/config.yaml`
or `/etc/defense-kit/config.yaml`):

```yaml
pipelines:
  my_pipeline:
    categories:
      - rootkit
      - credentials
      - ssh
      - processes
    tools:
      prefer_external: true
      skip:
        - clamscan   # too slow for this use case
```

Run a custom pipeline:

```bash
defense-kit scan --pipeline my_pipeline
```

---

## Pipeline Comparison

```
Coverage (categories)
 30 │ full_scan ████████████████████████████████████████
  8 │ incident_response ████████████████
  6 │ quick_monitor ████████████
    └────────────────────────────────────────────
      0s        30s        60s       120s     300s
                         Duration →
```

Choose based on your operational context:
- **Scheduled audit** → `full_scan` (nightly or weekly)
- **Continuous monitoring** → `quick_monitor` (every 5 minutes via `/loop`)
- **Active incident** → `incident_response` (immediately, with `--stream --copilot`)
