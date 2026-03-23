# Defense-Kit v2 — Comprehensive Defensive Security Toolkit

**Date:** 2026-03-21
**Status:** Draft
**Author:** erfan + Claude

---

## 1. Problem Statement

An AWS key leak occurred with two possible vectors: a compromised remote server or exposure through a vulnerable app behind Cloudflare Zero Trust. There is no single tool that provides comprehensive endpoint security covering malware detection, rootkit scanning, credential leak detection, persistence auditing, supply chain verification, and system hardening — all in one lightweight CLI with AI-assisted recommendations.

Existing tools (Wazuh, Lynis, osquery, etc.) each cover 5-6 areas at most, require heavy infrastructure, and provide no intelligent remediation workflow.

## 2. Goals

- Scan Linux laptops and remote servers across 30 security categories
- Detect malware, backdoors, rootkits, supply chain attacks, credential leaks
- Provide AI-powered recommendations that correlate findings across categories
- Interactive approve-then-fix workflow with rollback capability
- Continuous monitoring via Claude `/loop` integration
- Layered reporting: terminal, JSON, HTML dashboard, alerts (Slack/email/webhook)

## 3. Non-Goals

- macOS support (deferred to future version)
- Windows support
- Building a SIEM or log aggregation platform
- Replacing enterprise tools like Wazuh/CrowdStrike for large fleet management

## 4. Architecture

### 4.1 Stack

| Layer | Technology | Role |
|-------|-----------|------|
| Scanner engine | Go | Single binary, parallel scanning, system access, external tool orchestration |
| Python wrappers | Python | Optional tool integrations where Python libraries are superior |
| Copilot | Claude agents | AI recommendations, approve-fix workflow, finding correlation |
| Container | Docker (Kali) | Isolated code/dependency/container scanning |
| Monitoring | Claude `/loop` | Continuous periodic re-scans with diff reporting |

### 4.2 Execution Model

```
User → Go binary → ┬→ Native Go scanners (30 categories)
                    ├→ External tools (rkhunter, ClamAV, trivy...)
                    ├→ Python wrappers (optional, when needed)
                    ├→ Reports (JSON, HTML, terminal)
                    ├→ Alerts (Slack, email, webhook)
                    └→ Claude copilot (recommendations, approve→fix)
```

- **Hybrid deployment**: host scripts for full OS visibility + Docker for isolated code/dep scanning
- **Go binary controls Python**: subprocess execution for specific tool wrappers
- **Layered tool usage**: core scans work with pure Go/bash, external tools enhance detection when available

### 4.3 Directory Structure

```
defense-kit/
├── defense-kit-cli/                # Go binary (all Go code)
│   ├── cmd/defense-kit/main.go     # CLI entry point (cobra)
│   ├── internal/
│   │   ├── scanner/                # 30 scan category packages
│   │   │   ├── engine.go           # Parallel scan orchestrator
│   │   │   ├── registry.go         # Scanner plugin registry
│   │   │   ├── result.go           # Finding/severity types
│   │   │   ├── credentials/
│   │   │   ├── persistence/
│   │   │   ├── processes/
│   │   │   ├── supply_chain/
│   │   │   ├── file_integrity/
│   │   │   ├── network/
│   │   │   ├── rootkit/
│   │   │   ├── containers/
│   │   │   ├── ssh/
│   │   │   ├── browser/
│   │   │   ├── dns/
│   │   │   ├── users/
│   │   │   ├── logs/
│   │   │   ├── filesystem/
│   │   │   ├── scheduled/
│   │   │   ├── memory/
│   │   │   ├── ld_preload/
│   │   │   ├── pam/
│   │   │   ├── boot/
│   │   │   ├── systemd_inject/
│   │   │   ├── shell_rc/
│   │   │   ├── git_hooks/
│   │   │   ├── clipboard/
│   │   │   ├── capabilities/
│   │   │   ├── firewall/
│   │   │   ├── package_manager/
│   │   │   ├── timestomp/
│   │   │   ├── env_vars/
│   │   │   ├── vpn/
│   │   │   └── swap/
│   │   ├── hardener/               # Approve → fix engine
│   │   │   ├── engine.go
│   │   │   ├── os.go
│   │   │   ├── ssh.go
│   │   │   ├── firewall.go
│   │   │   ├── git.go
│   │   │   └── docker.go
│   │   ├── reporter/               # 4-level reporting
│   │   │   ├── terminal.go
│   │   │   ├── json.go
│   │   │   ├── html.go
│   │   │   └── alert.go
│   │   ├── monitor/                # Baseline diff engine
│   │   │   └── watcher.go
│   │   ├── tools/                  # External tool management
│   │   │   ├── registry.go
│   │   │   ├── runner.go
│   │   │   └── python.go
│   │   └── config/                 # Policy & config
│   │       ├── config.go
│   │       └── policy.go
│   ├── scripts/python/             # Python tool wrappers
│   ├── templates/                  # HTML report templates
│   ├── go.mod
│   ├── go.sum
│   └── Makefile
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-entrypoint.sh
├── .claude/
│   ├── agents/
│   │   ├── orchestrator.md
│   │   ├── scanner.md
│   │   └── hardener.md
│   └── skills/defense-kit/
│       ├── SKILL.md
│       ├── scans/                  # Per-category documentation
│       │   ├── credentials/
│       │   ├── persistence/
│       │   ├── processes/
│       │   ├── supply-chain/
│       │   ├── file-integrity/
│       │   ├── network/
│       │   ├── rootkit/
│       │   ├── containers/
│       │   ├── ssh/
│       │   ├── browser/
│       │   ├── dns/
│       │   ├── users/
│       │   ├── logs/
│       │   ├── filesystem/
│       │   ├── scheduled/
│       │   ├── memory/
│       │   ├── ld-preload/
│       │   ├── pam/
│       │   ├── boot/
│       │   ├── systemd-inject/
│       │   ├── shell-rc/
│       │   ├── git-hooks/
│       │   ├── clipboard/
│       │   ├── capabilities/
│       │   ├── firewall/
│       │   ├── package-manager/
│       │   ├── timestomp/
│       │   ├── env-vars/
│       │   ├── vpn/
│       │   └── swap/
│       └── reference/
│           ├── SCAN_INDEX.md
│           ├── OUTPUT_STRUCTURE.md
│           └── templates/
├── tools/
│   ├── REGISTRY.md                 # External tool catalog
│   ├── PIPELINES.md                # Scan chain definitions
│   ├── preflight.sh                # Tool availability checker
│   ├── kali/
│   │   ├── config.json
│   │   └── install.sh
│   └── wrappers/                   # Python output normalizers
├── rules/
│   ├── semgrep/
│   └── nuclei/
├── rules.local/
├── policies/
│   └── baseline.yml
├── outputs/
├── target/
├── CLAUDE.md
├── README.md
└── LICENSE
```

## 5. Scanner Engine

### 5.1 Scanner Interface

Every scan category implements:

```go
type Scanner interface {
    Name() string
    Category() string
    Description() string
    Scan(ctx context.Context, opts ScanOptions) ([]Finding, error)
    RequiredTools() []string
    OptionalTools() []string
    RequiresRoot() bool
    Available() bool
}
```

### 5.2 Finding Type

```go
type Finding struct {
    ID          string
    Scanner     string
    Severity    Severity          // CRITICAL, HIGH, MEDIUM, LOW
    Title       string
    Detail      string
    Evidence    string
    Location    string
    Remediation string
    CanAutoFix  bool
    References  []string
    Metadata    map[string]string
}
```

### 5.3 Execution Flow

1. Registry discovers all 30 scanners
2. Preflight checks which external tools are available
3. Engine runs scanners in parallel (goroutines, configurable concurrency)
4. Each scanner tries external tool first, falls back to native Go checks
5. Engine aggregates all findings
6. Severity classification applied
7. Results passed to reporter pipeline

### 5.4 Tool Runner

```go
type ToolRunner interface {
    Run(ctx context.Context, tool string, args []string) ([]byte, error)
    RunPython(ctx context.Context, script string, args []string) ([]byte, error)
    Available(tool string) bool
}
```

## 6. 30 Scan Categories

| # | Category | What It Detects | Key Tools |
|---|----------|----------------|-----------|
| 1 | credentials | Leaked keys, tokens, passwords in files/env/history | gitleaks, trufflehog |
| 2 | persistence | Unauthorized cron, systemd, init scripts, authorized_keys | native Go + auditd |
| 3 | processes | Reverse shells, crypto miners, unknown daemons | ps, lsof, /proc |
| 4 | supply_chain | Tampered binaries, CVEs, unsigned packages | trivy, grype, debsums |
| 5 | file_integrity | Unexpected SUID, modified system files | AIDE, sha256sum |
| 6 | network | Open ports, C2 connections, suspicious outbound | nmap, ss, netstat |
| 7 | rootkit | Hidden kernel modules, syscall hooks | rkhunter, chkrootkit |
| 8 | containers | Privileged containers, Docker socket exposure | hadolint, dockle, trivy |
| 9 | ssh | Unauthorized keys, brute force, weak config | ssh-audit |
| 10 | browser | Saved passwords in plaintext, risky extensions | native Go |
| 11 | dns | DNS exfiltration, rogue resolvers, C2 domains | resolvectl, dig |
| 12 | users | Unexpected UID 0, sudoers mods, privilege escalation | native Go |
| 13 | logs | Truncated logs, gaps, disabled logging | native Go |
| 14 | filesystem | Hidden files, world-writable dirs, tmp abuse | native Go |
| 15 | scheduled | at jobs, systemd timers, anacron | native Go |
| 16 | memory | Processes with deleted binaries, injected libs | /proc inspection |
| 17 | ld_preload | LD_PRELOAD hijacking, rogue .so files | native Go |
| 18 | pam | Modified PAM configs, unauthorized modules | native Go |
| 19 | boot | GRUB tampering, initramfs modification | native Go |
| 20 | systemd_inject | User service files, drop-in overrides, generators | native Go |
| 21 | shell_rc | Malicious .bashrc/.profile/.zshrc entries | native Go |
| 22 | git_hooks | Malicious pre-commit/post-checkout hooks | native Go |
| 23 | clipboard | xinput sniffers, X11 keyloggers | native Go |
| 24 | capabilities | Unexpected SUID/SGID, elevated caps | native Go |
| 25 | firewall | Unexpected iptables/nftables rules, NAT forwarding | ufw, iptables |
| 26 | package_manager | Unauthorized repos, GPG key tampering | apt, dpkg, rpm |
| 27 | timestomp | mtime/ctime anomalies (anti-forensics) | native Go |
| 28 | env_vars | Malicious PATH, LD_*, PROMPT_COMMAND, proxy hijack | native Go |
| 29 | vpn | WireGuard/VPN misconfigs, rogue peers, traffic leaks | native Go |
| 30 | swap | Secrets in swap, credential-leaking core dumps | native Go |

## 7. Hardener

### 7.1 Interface

```go
type Hardener interface {
    Name() string
    CanFix(finding Finding) bool
    Preview(finding Finding) FixPlan
    Apply(ctx context.Context, plan FixPlan) error
    Verify(ctx context.Context, plan FixPlan) error
    Rollback(ctx context.Context, plan FixPlan) error
}

type FixPlan struct {
    Finding     Finding
    Description string
    Changes     []FileChange
    Actions     []FixAction
    BackupPaths map[string]string
    Rollback    RollbackPlan
}
```

### 7.2 Approval Modes

| Mode | Behavior |
|------|----------|
| `interactive` | Ask for each finding (default) |
| `batch` | Show all, approve/reject in bulk |
| `auto-low` | Auto-fix LOW/MEDIUM, ask for HIGH/CRITICAL |
| `dry-run` | Show what would change, fix nothing |

### 7.3 Rollback

Every harden session generates `rollback-{timestamp}.sh` that undoes all applied fixes in reverse order. Backups are stored alongside the rollback script.

## 8. Reporter Pipeline

Four independent levels, any combination:

### Level 1 — Terminal
Real-time colored output with severity indicators, evidence, and recommended actions.

### Level 2 — JSON
Structured findings at `outputs/{scan-id}/findings.json`. Machine-parseable, suitable for piping to other tools.

### Level 3 — HTML Dashboard
Visual report with severity breakdown chart, per-category findings table, expandable evidence, and diff from previous scan.

### Level 4 — Alerts
Push notifications via Slack webhook, email (SMTP), or generic webhook. Configurable severity threshold per channel in `policies/baseline.yml`:

```yaml
alerts:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    min_severity: high
  email:
    to: user@example.com
    min_severity: critical
  webhook:
    url: ${WEBHOOK_URL}
    min_severity: medium
```

## 9. Severity Classification

| Severity | Example | Default Action |
|----------|---------|---------------|
| CRITICAL | Active reverse shell, rootkit, leaked AWS key in history | Immediate alert + block recommendation |
| HIGH | Unknown SUID binary, unauthorized SSH key, suspicious cron | Alert + recommend fix |
| MEDIUM | Outdated package with CVE, weak SSH config | Report + suggest hardening |
| LOW | Missing best practice, informational | Log only |

## 10. Monitor Mode

### 10.1 `/loop` Integration

```
/loop 5m /defense-kit monitor
```

Every interval, Claude runs `defense-kit scan --quick --diff`, compares against baseline, reports only changes.

### 10.2 Quick Scan Subset

Monitor mode runs a fast subset: processes, network connections, file integrity, persistence mechanisms, SSH keys, RC files.

### 10.3 Standalone Scheduling

For continuous monitoring without an active Claude session:

```
defense-kit schedule enable --interval 6h
```

Creates a systemd timer (preferred) or cron job that runs `defense-kit scan --quick --diff` on the specified interval. Results saved to `outputs/`, alerts fired via configured channels.

```go
type Schedule struct {
    Interval    time.Duration
    ScanMode    string        // "quick" (default), "full"
    Backend     string        // "systemd" (preferred), "cron" (fallback)
    AlertOnNew  bool          // fire alerts for new findings (default: true)
}
```

- `schedule enable` — creates systemd timer unit or cron entry
- `schedule disable` — removes the timer/cron entry
- `schedule status` — shows backend, interval, next run, last run result
- When Claude is available, it reads latest scheduled scan results and provides AI analysis

### 10.4 Baseline Management

- `defense-kit scan` creates initial baseline at `outputs/baseline.json`
- `defense-kit monitor` diffs against baseline
- `defense-kit baseline update` promotes current state to new baseline
- `defense-kit baseline diff` shows changes without updating

## 11. CLI Commands

```
defense-kit scan                    # full scan, all 30 categories
defense-kit scan --quick            # fast subset for monitoring
defense-kit scan --category rootkit # single category
defense-kit scan --diff             # compare against baseline
defense-kit harden                  # interactive fix workflow
defense-kit harden --dry-run        # show fixes without applying
defense-kit monitor                 # quick scan + diff (for /loop)
defense-kit comply                  # map findings to CIS/SOC2/OWASP
defense-kit baseline update         # set current as baseline
defense-kit baseline diff           # show changes from baseline
defense-kit tools check             # preflight: what's installed
defense-kit report --html           # regenerate HTML from last scan
defense-kit schedule enable --interval 6h  # create systemd timer or cron job
defense-kit schedule disable               # remove scheduled scan
defense-kit schedule status                # show next run time
```

## 12. Tool Registry

30+ external tools organized in `tools/REGISTRY.md`:

| Category | Tools |
|----------|-------|
| OS audit | lynis, chkrootkit, rkhunter |
| Network | nmap, ss, netstat, tcpdump, ufw, iptables, nftables |
| Code | semgrep, bandit |
| Secrets | gitleaks, trufflehog |
| Dependencies | trivy, grype, pip-audit, npm audit |
| Containers | hadolint, dockle, trivy |
| SSH | ssh-audit |
| Malware | ClamAV (clamscan/freshclam) |
| File integrity | AIDE, sha256sum |
| Process | ps, lsof, /proc |
| Forensics | debsums, rpm -V |
| DNS | resolvectl, dig |
| Firewall | ufw, iptables, nftables |
| Package | apt, dpkg, rpm |
| Boot | grub, initramfs-tools |
| PAM | pam-auth-update |

## 13. Pipelines

Defined in `tools/PIPELINES.md`:

### full_scan
All 30 categories with maximum parallelism. External tools preferred when available.

### quick_monitor
Fast subset (processes, network, files, persistence, SSH keys) for `/loop` monitoring.

### incident_response
Targeted scan for active compromise indicators: reverse shells, rootkits, unauthorized access, credential theft.

## 14. Claude Copilot Layer

### Orchestrator Agent
Coordinates scan/harden/monitor. Detects environment, dispatches scanners in parallel, aggregates results, generates reports.

### Scanner Agent
Runs `defense-kit scan` on host or in Docker. Follows REGISTRY.md for tool commands, PIPELINES.md for execution order. Read-only.

### Hardener Agent
Receives findings with `CanAutoFix=true`. Explains each in plain English, waits for approval, applies fix, verifies, generates rollback.

### AI Value-Add
Claude correlates findings across categories. Example: new cron job + modified .bashrc + outbound connection to unknown IP = coordinated compromise, not three independent findings.

## 15. Privilege Model

### 15.1 Privilege Levels

| Mode | Required Privilege | Reason |
|------|-------------------|--------|
| `scan` (user-space) | Regular user | Read home dirs, user processes, user cron |
| `scan` (system) | Root or sudo | Read /proc, kernel modules, PAM, boot, all users |
| `harden` | Root or sudo | Modify SSH config, firewall, systemd units |
| `monitor` | Same as scan mode used | Periodic re-scan |
| `tools check` | Regular user | Check tool availability |

### 15.2 Privilege Escalation Strategy

- Binary runs as regular user by default
- Scanners that need root declare `RequiresRoot() bool` in their interface
- Engine groups scanners: run unprivileged scanners first, then prompt once for sudo to run privileged scanners
- If sudo unavailable, privileged scanners are skipped with a warning (degraded scan, not a failure)
- Hardener always requires root — refuses to start without it

### 15.3 Command Execution Safety

- **Never use shell interpretation** — all commands use `exec.CommandContext` with explicit argv (no `sh -c`)
- `FixPlan.Actions` uses structured actions, not string commands:

```go
type FixAction struct {
    Type       ActionType  // FileEdit, FileCreate, FileDelete, ServiceRestart, CommandExec
    Target     string      // file path or service name
    Args       []string    // explicit argv, never shell-interpolated
    Validation []string     // argv to verify the action succeeded (no shell interpretation)
}
```

- File paths in actions are validated against an allowlist of system config directories
- No user-supplied input flows into command arguments without sanitization

## 16. Error Handling

### 16.1 Scanner Failure Modes

```go
type ScanResult struct {
    Scanner  string
    Status   ScanStatus  // Success, Partial, Failed, Skipped
    Findings []Finding
    Error    error       // non-nil for Partial/Failed
    Duration time.Duration
}

type ScanStatus int
const (
    ScanSuccess ScanStatus = iota
    ScanPartial   // some findings valid, scanner hit an error mid-scan
    ScanFailed    // scanner could not run at all
    ScanSkipped   // missing tools or insufficient privileges
)
```

### 16.2 Failure Behavior

- Per-scanner timeout: configurable, default 60s per scanner, 300s for heavy scanners (ClamAV)
- Scanner panic: recovered with `recover()`, logged, marked as Failed, other scanners continue
- Partial results: findings collected before error are valid and included in report
- External tool unexpected output: logged as warning, scanner falls back to native Go checks
- Resource exhaustion: configurable concurrency limit (default `runtime.NumCPU()`), `--concurrency` flag

### 16.3 Hardener Failure Behavior

- If a fix fails: stop, do not continue to next fix, report failure
- If verification fails after fix: auto-rollback that specific fix
- If rollback fails: halt with CRITICAL alert, print manual recovery steps

## 17. Scan Options

```go
type ScanOptions struct {
    TargetPaths   []string      // paths to scan (default: /, /home)
    ExcludePaths  []string      // paths to skip
    Categories    []string      // which scan categories to run (default: all)
    Timeout       time.Duration // per-scanner timeout
    Concurrency   int           // max parallel scanners
    UseExtTools   bool          // allow external tools (default: true)
    PolicyPath    string        // path to baseline.yml
    Quick         bool          // fast subset for monitoring
    Diff          bool          // compare against baseline
    Verbose       bool          // detailed output
}
```

## 18. Baseline & Diffing

### 18.1 Baseline Schema

```json
{
  "version": 1,
  "created_at": "2026-03-21T14:30:22Z",
  "host": "erfan-laptop",
  "scan_id": "dk-20260321-143022",
  "findings": [...],
  "system_state": {
    "processes_hash": "sha256:...",
    "cron_hash": "sha256:...",
    "authorized_keys_hash": "sha256:...",
    "systemd_units_hash": "sha256:...",
    "open_ports": [22, 80, 443],
    "suid_binaries": ["/usr/bin/sudo", "/usr/bin/passwd"]
  },
  "acknowledged": ["finding-id-1", "finding-id-2"]
}
```

### 18.2 Diff Algorithm

- Findings matched by deterministic ID: `{scanner}-{sha256(location + title)[:12]}`
- Diff categories: `new` (not in baseline), `resolved` (in baseline, not in current), `changed` (severity changed), `acknowledged` (user accepted the risk)
- `baseline update` records current findings and system state; findings present at update time are marked `acknowledged` (known risks, not alerted on again)
- `baseline diff` is read-only comparison, no state change

## 19. Configuration

### 19.1 Config File

Location: `~/.config/defense-kit/config.yml` (user) or `/etc/defense-kit/config.yml` (system).

```yaml
scan:
  concurrency: 4
  timeout: 60s
  timeout_heavy: 300s    # ClamAV, trivy full scan
  exclude_paths:
    - /proc
    - /sys
    - /dev
  categories:            # empty = all
    - credentials
    - rootkit

tools:
  prefer_external: true
  python_path: /usr/bin/python3
  tool_paths:            # override auto-discovery
    rkhunter: /usr/local/bin/rkhunter

alerts:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    min_severity: high
  email:
    to: user@example.com
    smtp_host: smtp.example.com
    min_severity: critical
  webhook:
    url: ${WEBHOOK_URL}
    min_severity: medium
    hmac_secret: ${WEBHOOK_HMAC_SECRET}
    require_tls: true

monitor:
  interval: 5m
  quick_categories:
    - processes
    - network
    - file_integrity
    - persistence
    - ssh
    - shell_rc
```

### 19.2 Precedence

Defaults < `/etc/defense-kit/config.yml` < `~/.config/defense-kit/config.yml` < `policies/baseline.yml` < environment variables < CLI flags.

## 20. Hardener Registry

### 20.1 Dispatch

```go
type HardenerRegistry struct {
    hardeners []Hardener
}

func (r *HardenerRegistry) FindHardener(f Finding) (Hardener, error) {
    var candidates []Hardener
    for _, h := range r.hardeners {
        if h.CanFix(f) {
            candidates = append(candidates, h)
        }
    }
    if len(candidates) == 0 {
        return nil, ErrNoHardener
    }
    if len(candidates) > 1 {
        return candidates[0], nil // first registered wins (priority order)
    }
    return candidates[0], nil
}
```

### 20.2 Validation

At startup, the hardener registry validates that every scanner category with `CanAutoFix` findings has at least one matching hardener registered. Mismatches are logged as warnings.

## 21. Rollback System

### 21.1 Structured Rollback

```go
type RollbackStep struct {
    Description string
    Action      FixAction     // reverse of the original action
    Verify      []string      // argv to confirm rollback succeeded (no shell interpretation)
    BackupPath  string        // path to backup file (if file was modified)
}

type RollbackPlan struct {
    SessionID string
    Timestamp time.Time
    Steps     []RollbackStep  // executed in reverse order
}
```

### 21.2 Execution

- Steps execute in reverse order (last applied, first rolled back)
- Each step verifies success before proceeding
- If a step fails: halt, print remaining manual steps, alert user
- Rollback plan saved as both structured JSON and executable shell script

## 22. Claude Copilot Integration

### 22.1 Interface

Go binary communicates with Claude agents via structured JSON on stdout:

1. User runs `/defense-kit scan`
2. Claude reads SKILL.md, invokes orchestrator agent
3. Orchestrator runs `defense-kit scan` via Bash tool
4. Go binary outputs JSON findings to `outputs/{scan-id}/findings.json`
5. Orchestrator reads JSON via Read tool
6. Claude interprets findings, correlates across categories, generates recommendations
7. For hardening: Claude presents findings to user, gets approval, runs `defense-kit harden --finding <id> --approve`

### 22.2 Finding Correlation

Claude receives all findings as context and identifies patterns:
- Multiple findings pointing to same attack chain
- Temporal correlation (things that changed around the same time)
- Known attack patterns (e.g., reverse shell + cron persistence + credential theft)

## 23. Deployment Model

### 23.1 Host + Docker Hybrid

```
Host (Go binary)
  ├── Runs directly: OS, kernel, process, network, SSH, boot, PAM scans
  │   (needs real system access)
  └── Launches Docker: code, dependency, container, secret scans
      (isolated, reproducible)
```

- Go binary always runs on host
- Binary detects Docker availability, launches container for isolated scans
- Container results collected via mounted `outputs/` volume
- If Docker unavailable, all scans run on host (degraded isolation, full functionality)

## 24. Webhook Security

- All webhooks require HTTPS (configurable override for local testing)
- Payloads signed with HMAC-SHA256 using `webhook.hmac_secret`
- Signature sent in `X-Defense-Kit-Signature` header
- Sensitive evidence is redacted in alert payloads (full details in local JSON only)

## 25. HTML Report Security

- Reports are static HTML files, not served
- All evidence strings HTML-escaped in template rendering
- No inline JavaScript — pure HTML + CSS
- Reports contain a warning header: "Contains security findings — do not share publicly"

## 26. Finding ID Generation

Format: `{scanner}-{sha256(location + title)[:12]}`

Example: `rootkit-a3f8c2e91b04`

Deterministic — same finding produces same ID across runs, enabling stable baseline diffing and deduplication.

## 27. External Tool Versioning

### 27.1 Minimum Supported Versions

Defined in `tools/REGISTRY.md` per tool. The Go binary checks tool version at preflight and warns if below minimum.

### 27.2 Output Format Detection

Tool runner detects output format version (e.g., trivy JSON schema v1 vs v2) and selects the appropriate parser. Unknown formats fall back to raw text capture with a warning.

## 28. Python Wrapper Contract

### 28.1 Interface

Python wrappers follow a standard contract:

- **Input**: CLI arguments (paths, options)
- **Output**: JSON to stdout following the Finding schema
- **Exit codes**: 0 = success, 1 = error (stderr has details), 2 = tool not found
- **Location**: `defense-kit-cli/scripts/python/`

### 28.2 When Used

Python wrappers are optional. Used only when a Python library provides significantly better functionality than a Go native implementation or CLI tool (e.g., specific ML-based detection models).

## 29. Scanner Grouping

### 29.1 Physical Package Groups

While 30 logical categories exist, related scanners share physical packages to reduce duplication:

| Package | Logical Categories |
|---------|-------------------|
| `persistence/` | persistence, scheduled, systemd_inject |
| `process/` | processes, memory, clipboard |
| `filesystem/` | file_integrity, filesystem, timestomp, capabilities, swap |
| `environment/` | ld_preload, env_vars, shell_rc, pam |
| `network/` | network, dns, firewall, vpn |
| `auth/` | ssh, users, browser |
| `system/` | rootkit, boot, logs, package_manager |
| `code/` | credentials, supply_chain, containers, git_hooks |

Each package can contain multiple scanner implementations that share utility code.

## 30. Testing Strategy

### 30.1 Unit Tests

- Each scanner has unit tests with mocked tool output (captured from real tool runs)
- Hardener tests use temporary directories and mock file systems
- Reporter tests verify JSON schema, HTML escaping, alert payload format

### 30.2 Integration Tests

- Docker container with planted vulnerabilities (weak SSH config, SUID binaries, fake cron jobs, test malware signatures)
- Test matrix: with external tools installed vs. native-only fallback
- Hardener integration tests run in disposable containers

### 30.3 E2E Tests

- Full scan → harden → verify → rollback cycle in a purpose-built VM
- Baseline → modify system → monitor → verify diff detected

## 31. Migration from v1

### 31.1 Backward Compatibility

- `/defense-kit scan` skill interface preserved — same user experience
- `policies/baseline.yml` format compatible — v2 reads v1 policies
- `outputs/` directory structure extended, not replaced

### 31.2 Phased Delivery

1. **Phase 1**: Go binary with core scanner engine + 8 scanner groups (native Go only)
2. **Phase 2**: External tool integration (REGISTRY.md, preflight, tool runner)
3. **Phase 3**: Hardener engine with approve-fix workflow
4. **Phase 4**: Reporter pipeline (all 4 levels)
5. **Phase 5**: Monitor mode + baseline management
6. **Phase 6**: Claude agent updates (orchestrator, scanner, hardener)
7. **Phase 7**: Docker hybrid deployment
8. **Phase 8**: Compliance mapping (`comply` command)

## 32. Compliance Mapping (Deferred — Phase 8)

The `comply` command maps findings to compliance frameworks. Initial target: CIS Benchmarks for Linux. Future: SOC2, OWASP. Each finding includes a `References` field that can contain CIS control IDs, enabling automatic mapping. Full compliance report format to be designed in Phase 8.

## 33. Security Principles

1. **Scan mode is read-only** — never modifies the system
2. **Harden requires approval** — every change needs explicit user consent
3. **Always rollback** — every fix generates a reversible rollback script
4. **Log everything** — all actions recorded for audit trail
5. **Layered detection** — works with zero deps, better with external tools
6. **Never break SSH/networking** — hardener validates connectivity before and after changes
7. **No shell interpretation** — all command execution uses explicit argv
8. **Least privilege** — scan as user when possible, sudo only when needed
9. **Secure reporting** — HTML escaped, webhooks signed, evidence redacted in alerts
