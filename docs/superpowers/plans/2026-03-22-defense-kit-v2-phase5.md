# Defense-Kit v2 Phase 5: Monitor Mode + Scheduling

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add continuous monitoring via the `monitor` command (designed for Claude `/loop`), standalone scheduling via systemd timers or cron jobs, and the `schedule` CLI command to manage them.

**Architecture:** `monitor` runs a quick scan + baseline diff and reports only changes. `schedule` creates/removes systemd timer units or cron entries. Both use the existing scan engine, baseline, and alert systems.

**Tech Stack:** Go 1.22+, systemd unit file generation, crontab manipulation

**Spec:** `docs/superpowers/specs/2026-03-21-defense-kit-v2-design.md` (Sections 10, 11)

---

## File Map

```
defense-kit-cli/
├── internal/
│   ├── monitor/
│   │   ├── monitor.go          # Quick scan + diff logic
│   │   └── monitor_test.go
│   └── schedule/
│       ├── schedule.go         # Systemd timer / cron management
│       └── schedule_test.go
└── cmd/defense-kit/
    └── main.go                 # Add monitor + schedule commands
```

---

### Task 1: Monitor — Quick Scan + Baseline Diff

**Files:**
- Create: `defense-kit-cli/internal/monitor/monitor.go`
- Create: `defense-kit-cli/internal/monitor/monitor_test.go`

- [ ] **Step 1: Write failing tests**

Tests:
- TestMonitor_RunQuickScan — runs quick scan with mock registry, returns results
- TestMonitor_DiffAgainstBaseline — compares current scan against saved baseline, reports new/resolved/changed
- TestMonitor_FirstRunCreatesBaseline — when no baseline exists, creates one
- TestMonitor_ReportsOnlyChanges — unchanged findings not in output

- [ ] **Step 2: Implement monitor.go**

```go
package monitor

type Monitor struct {
    registry     *scanner.Registry
    baselinePath string
    outputDir    string
}

type MonitorResult struct {
    ScanResults []scanner.ScanResult
    Diff        baseline.DiffResult
    IsFirstRun  bool
    BaselinePath string
}

func New(registry *scanner.Registry, baselinePath, outputDir string) *Monitor

func (m *Monitor) Run(ctx context.Context, opts scanner.ScanOptions) (MonitorResult, error)
```

Run:
1. Force opts.Quick = true if not already set
2. Run scan via scanner.NewEngine(m.registry).Run()
3. Collect all findings
4. Load baseline (if missing → first run, save current as baseline)
5. If not first run → compute diff
6. Save current scan as latest (not overwrite baseline)
7. Return MonitorResult with diff

- [ ] **Step 3: Run tests — pass**
- [ ] **Step 4: Commit**

---

### Task 2: Schedule — Systemd Timer + Cron Management

**Files:**
- Create: `defense-kit-cli/internal/schedule/schedule.go`
- Create: `defense-kit-cli/internal/schedule/schedule_test.go`

- [ ] **Step 1: Write failing tests**

Tests:
- TestSchedule_GenerateSystemdUnit — generates valid .service and .timer unit files
- TestSchedule_GenerateCronEntry — generates valid crontab line
- TestSchedule_ParseInterval — "6h" → 6*time.Hour, "30m" → 30*time.Minute
- TestSchedule_DetectBackend — prefers systemd if systemctl exists, falls back to cron
- TestSchedule_StatusNoSchedule — returns not-scheduled status

- [ ] **Step 2: Implement schedule.go**

```go
package schedule

type Backend string
const (
    BackendSystemd Backend = "systemd"
    BackendCron    Backend = "cron"
)

type Schedule struct {
    Interval time.Duration
    ScanMode string    // "quick" or "full"
    Backend  Backend
    BinaryPath string // path to defense-kit binary
}

type Status struct {
    Enabled   bool
    Backend   Backend
    Interval  time.Duration
    NextRun   time.Time
    LastRun   time.Time
}

func DetectBackend() Backend  // systemctl exists → systemd, else cron

func Enable(s Schedule) error   // create timer/cron entry
func Disable() error            // remove timer/cron entry
func GetStatus() (Status, error)

// Systemd helpers (exported for testing)
func GenerateServiceUnit(binaryPath string) string  // returns unit file content
func GenerateTimerUnit(interval time.Duration) string

// Cron helpers
func GenerateCronEntry(binaryPath string, interval time.Duration) string
```

Systemd unit files:
```
# defense-kit.service
[Unit]
Description=Defense-Kit Security Scan

[Service]
Type=oneshot
ExecStart={binaryPath} scan --quick --diff --alert
```

```
# defense-kit.timer
[Unit]
Description=Defense-Kit Scheduled Scan

[Timer]
OnBootSec=5min
OnUnitActiveSec={interval}

[Install]
WantedBy=timers.target
```

Cron entry:
```
*/360 * * * * {binaryPath} scan --quick --diff --alert >> /var/log/defense-kit.log 2>&1
```

Enable:
- Systemd: write unit files to ~/.config/systemd/user/, run systemctl --user daemon-reload && enable --now
- Cron: append to crontab via `crontab -l | grep -v defense-kit; echo "entry"` pattern

Disable:
- Systemd: systemctl --user disable --now, remove files
- Cron: filter out defense-kit lines from crontab

- [ ] **Step 3: Run tests — pass**
- [ ] **Step 4: Commit**

---

### Task 3: Wire Monitor + Schedule to CLI

**Files:**
- Modify: `defense-kit-cli/cmd/defense-kit/main.go`

- [ ] **Step 1: Add monitor command**

```go
monitorCmd := &cobra.Command{
    Use:   "monitor",
    Short: "Quick scan + diff against baseline (for /loop)",
    RunE:  runMonitor,
}
```

runMonitor:
1. Load config
2. Create DefaultRegistry
3. Create Monitor with baseline path and output dir
4. Run monitor
5. If first run → print "Baseline created"
6. Else → print diff: new findings, resolved findings, changed findings
7. If --alert flag → dispatch alerts for new findings only

- [ ] **Step 2: Add schedule command**

```go
scheduleCmd := &cobra.Command{
    Use:   "schedule",
    Short: "Manage scheduled scans",
}
scheduleEnableCmd := &cobra.Command{
    Use:   "enable",
    Short: "Enable scheduled scanning",
    RunE:  runScheduleEnable,
}
scheduleEnableCmd.Flags().String("interval", "6h", "scan interval")
scheduleEnableCmd.Flags().String("mode", "quick", "scan mode: quick or full")

scheduleDisableCmd := &cobra.Command{
    Use:   "disable",
    Short: "Disable scheduled scanning",
    RunE:  runScheduleDisable,
}
scheduleStatusCmd := &cobra.Command{
    Use:   "status",
    Short: "Show schedule status",
    RunE:  runScheduleStatus,
}
```

- [ ] **Step 3: Build and test**

```bash
make build
./bin/defense-kit monitor --help
./bin/defense-kit schedule --help
./bin/defense-kit schedule status
```

- [ ] **Step 4: Commit**

---

### Task 4: E2E Verification

- [ ] **Step 1:** `./bin/defense-kit schedule status` — shows "not scheduled"
- [ ] **Step 2:** `go test ./... -race` — all pass
- [ ] **Step 3:** Final commit
