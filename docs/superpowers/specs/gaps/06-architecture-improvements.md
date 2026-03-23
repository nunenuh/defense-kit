# Gap 06: Architecture Improvements

**Priority:** MEDIUM
**Impact:** Structural changes for production-grade tooling

---

## 1. No Structured Logging

**Problem:** All output goes to `fmt.Fprintf(os.Stderr)`. No structured logging, no log levels, no log files.

**Fix:**
- Add `zerolog` or `slog` (stdlib) for structured JSON logging
- Log levels: DEBUG (scanner internals), INFO (scan progress), WARN (degraded scan), ERROR (failures)
- Log to file at `~/.defense-kit/defense-kit.log`
- Scan audit trail: log every scanner start/end, tool invocation, finding count

---

## 2. No Privilege Escalation Logic

**Problem:** The spec defines privilege-level scanner grouping (run unprivileged first, then batch sudo prompt). Not implemented — all scanners run at whatever privilege the binary has.

**Fix:**
- Engine groups scanners by `RequiresRoot()`
- Run unprivileged scanners first
- If any privileged scanners exist and we're not root: prompt once for sudo
- Re-launch privileged scanners under sudo
- If sudo unavailable: mark as ScanSkipped (already partially done)

---

## 3. No Output Directory Management

**Problem:** Scan outputs accumulate in `~/.defense-kit/outputs/` forever. No rotation, no cleanup.

**Fix:**
- `defense-kit outputs list` — show all scan results with dates and sizes
- `defense-kit outputs clean --keep 10` — keep last N scans, delete rest
- Auto-cleanup: configurable max outputs in config.yml
- Disk space check before scanning

---

## 4. No Signal Handling

**Problem:** If you Ctrl+C during a scan, it exits ungracefully. No cleanup of partial results, no "scan interrupted" status.

**Fix:**
- Catch SIGINT/SIGTERM
- Cancel context → scanners honor context cancellation
- Save partial results with status "interrupted"
- During hardening: if interrupted mid-apply, trigger rollback

---

## 5. No Progress Reporting

**Problem:** Full scan takes 60-90 seconds with no output until completion. User doesn't know if it's stuck.

**Fix:**
- Real-time progress: `[5/31] Scanning: rootkit...`
- Show elapsed time per scanner
- Show which scanners are running (parallel indicator)
- Final summary with per-scanner timing

---

## 6. Config Validation

**Problem:** Config file is loaded but never validated. Invalid severity strings, missing required fields, or typos silently produce defaults.

**Fix:**
- Validate all fields on load
- Error on unknown keys (catch typos)
- Validate webhook URLs are valid URLs
- Validate severity strings match known values
- Warn on empty alert configs when `--alert` is used

---

## 7. No Plugin System

**Problem:** Adding a new scanner requires modifying Go code and recompiling. Can't extend without rebuilding.

**Fix (future):**
- Script-based scanners: drop a shell/python script in `~/.defense-kit/scanners.d/`
- Script follows convention: outputs JSON findings to stdout, exit code indicates status
- Go binary discovers and runs script-based scanners alongside native ones
- Enables community-contributed scanners without Go knowledge

---

## 8. No Remote Scanning

**Problem:** Defense-kit only scans the local machine. Can't scan a remote server without SSHing in and running it there.

**Fix (future):**
- `defense-kit scan --remote user@host` — SSH into remote, run scan, collect results
- Requires defense-kit binary on remote (or transfer it)
- Alternative: `defense-kit scan --remote user@host --agent` — deploy temporary agent
- Multi-host scanning: `defense-kit scan --hosts inventory.yml`

---

## 9. No Scan Profiles

**Problem:** Only two modes: full scan or quick scan. No way to create custom scan profiles.

**Fix:**
- Config-driven profiles:
```yaml
profiles:
  workstation:
    categories: [credentials, ssh, shell_rc, env_vars, processes, cron]
  server:
    categories: [ssh, firewall, users, rootkit, logs, network, persistence]
  ci:
    categories: [credentials, supply_chain, containers, git_hooks]
```
- `defense-kit scan --profile workstation`

---

## 10. Finding Deduplication Across Runs

**Problem:** Running scan twice produces duplicate findings in outputs. No cross-run deduplication.

**Fix:**
- Finding IDs are deterministic (already implemented)
- Track "first seen" and "last seen" timestamps per finding
- Don't re-alert on known findings (baseline handles this partially, but could be tighter)
- Show finding age in reports
