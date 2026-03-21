# Defense-Kit v2 Phase 3: Hardener Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the hardener engine that takes scan findings, presents recommended fixes, waits for user approval, applies fixes with backups, verifies success, and generates rollback scripts.

**Architecture:** HardenerRegistry dispatches findings to Hardener implementations. Each Hardener produces a FixPlan with structured FixActions (no shell interpretation). Engine handles backup → apply → verify → rollback lifecycle. Four approval modes: interactive, batch, auto-low, dry-run.

**Tech Stack:** Go 1.22+, exec.CommandContext, file backup/restore

**Spec:** `docs/superpowers/specs/2026-03-21-defense-kit-v2-design.md` (Sections 7, 15.3, 16.3, 20, 21)

---

## File Map

```
defense-kit-cli/
├── internal/
│   └── hardener/
│       ├── types.go          # Hardener, FixPlan, FixAction, RollbackPlan types
│       ├── registry.go       # HardenerRegistry — dispatch findings to hardeners
│       ├── engine.go         # Approval workflow, backup, apply, verify, rollback
│       ├── rollback.go       # Rollback plan execution + shell script generation
│       ├── ssh.go            # SSH config hardener
│       ├── firewall.go       # Firewall hardener (ufw)
│       ├── os.go             # OS sysctl hardener
│       ├── git.go            # Git config hardener
│       ├── hardener_test.go  # Tests for engine, registry, rollback
│       └── ssh_test.go       # Tests for SSH hardener
├── cmd/defense-kit/
│   └── main.go              # Add harden command
```

---

### Task 1: Hardener Types — FixAction, FixPlan, RollbackPlan

**Files:**
- Create: `defense-kit-cli/internal/hardener/types.go`
- Create: `defense-kit-cli/internal/hardener/hardener_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/hardener/hardener_test.go
package hardener

import (
	"testing"
)

func TestActionTypeString(t *testing.T) {
	tests := []struct {
		at   ActionType
		want string
	}{
		{FileEdit, "file_edit"},
		{FileCreate, "file_create"},
		{FileDelete, "file_delete"},
		{ServiceRestart, "service_restart"},
		{CommandExec, "command_exec"},
	}
	for _, tt := range tests {
		if got := tt.at.String(); got != tt.want {
			t.Errorf("ActionType(%d).String() = %s, want %s", tt.at, got, tt.want)
		}
	}
}

func TestApprovalModeString(t *testing.T) {
	tests := []struct {
		m    ApprovalMode
		want string
	}{
		{ModeInteractive, "interactive"},
		{ModeBatch, "batch"},
		{ModeAutoLow, "auto-low"},
		{ModeDryRun, "dry-run"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("ApprovalMode.String() = %s, want %s", got, tt.want)
		}
	}
}

func TestFixPlanHasRequiredFields(t *testing.T) {
	plan := FixPlan{
		Description: "Disable SSH root login",
		Actions: []FixAction{
			{
				Type:   FileEdit,
				Target: "/etc/ssh/sshd_config",
				Args:   []string{"PermitRootLogin", "no"},
			},
		},
	}
	if plan.Description == "" {
		t.Error("description required")
	}
	if len(plan.Actions) == 0 {
		t.Error("actions required")
	}
}
```

- [ ] **Step 2: Run test — should fail**

- [ ] **Step 3: Implement types.go**

```go
// internal/hardener/types.go
package hardener

import (
	"context"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type ActionType int

const (
	FileEdit ActionType = iota
	FileCreate
	FileDelete
	ServiceRestart
	CommandExec
)

func (a ActionType) String() string {
	switch a {
	case FileEdit:
		return "file_edit"
	case FileCreate:
		return "file_create"
	case FileDelete:
		return "file_delete"
	case ServiceRestart:
		return "service_restart"
	case CommandExec:
		return "command_exec"
	default:
		return "unknown"
	}
}

type ApprovalMode int

const (
	ModeInteractive ApprovalMode = iota
	ModeBatch
	ModeAutoLow
	ModeDryRun
)

func (m ApprovalMode) String() string {
	switch m {
	case ModeInteractive:
		return "interactive"
	case ModeBatch:
		return "batch"
	case ModeAutoLow:
		return "auto-low"
	case ModeDryRun:
		return "dry-run"
	default:
		return "unknown"
	}
}

// FixAction is a single atomic change. No shell interpretation.
type FixAction struct {
	Type       ActionType
	Target     string   // file path or service name
	Args       []string // explicit argv
	Validation []string // argv to verify success
}

// FixPlan describes what a hardener will do to fix a finding.
type FixPlan struct {
	Finding     scanner.Finding
	Description string
	Actions     []FixAction
	BackupPaths map[string]string // original → backup
	Rollback    RollbackPlan
}

// RollbackStep reverses a single FixAction.
type RollbackStep struct {
	Description string
	Action      FixAction
	Verify      []string // argv to confirm rollback
	BackupPath  string   // backup file to restore
}

// RollbackPlan contains all steps to undo a hardening session.
type RollbackPlan struct {
	SessionID string
	Timestamp time.Time
	Steps     []RollbackStep
}

// Hardener can fix specific types of findings.
type Hardener interface {
	Name() string
	CanFix(finding scanner.Finding) bool
	Preview(finding scanner.Finding) FixPlan
	Apply(ctx context.Context, plan FixPlan) error
	Verify(ctx context.Context, plan FixPlan) error
	Rollback(ctx context.Context, plan FixPlan) error
}

// HardenOptions configures a hardening session.
type HardenOptions struct {
	Mode       ApprovalMode
	OutputDir  string // where to save rollback scripts
	Findings   []scanner.Finding
	DryRun     bool
}
```

- [ ] **Step 4: Run tests — should pass**

- [ ] **Step 5: Commit**

---

### Task 2: Hardener Registry — Dispatch Findings to Hardeners

**Files:**
- Create: `defense-kit-cli/internal/hardener/registry.go`
- Modify: `defense-kit-cli/internal/hardener/hardener_test.go`

- [ ] **Step 1: Write failing tests for registry**

Test: Register hardeners, FindHardener returns correct one, FindHardener returns error for no match, priority ordering when multiple match.

- [ ] **Step 2: Implement registry.go**

```go
type HardenerRegistry struct {
    hardeners []Hardener
}

func NewHardenerRegistry() *HardenerRegistry
func (r *HardenerRegistry) Register(h Hardener)
func (r *HardenerRegistry) FindHardener(f scanner.Finding) (Hardener, error)
func (r *HardenerRegistry) FixableFindings(findings []scanner.Finding) []scanner.Finding
```

- `FindHardener`: iterate hardeners, return first that `CanFix(f)`, error if none
- `FixableFindings`: filter findings to only those with a matching hardener

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 3: Rollback System — Backup, Restore, Script Generation

**Files:**
- Create: `defense-kit-cli/internal/hardener/rollback.go`
- Modify: `defense-kit-cli/internal/hardener/hardener_test.go`

- [ ] **Step 1: Write failing tests**

Test: BackupFile creates copy, RestoreFile restores, GenerateRollbackScript creates executable .sh, RollbackPlan executes steps in reverse.

- [ ] **Step 2: Implement rollback.go**

```go
func BackupFile(src string, backupDir string) (string, error)  // copy file, return backup path
func RestoreFile(backupPath, originalPath string) error         // restore from backup
func GenerateRollbackScript(plan RollbackPlan, path string) error  // write .sh script
func ExecuteRollback(ctx context.Context, plan RollbackPlan) error  // run steps in reverse
```

- BackupFile: copy to `backupDir/{timestamp}-{basename}`
- GenerateRollbackScript: write bash script with `cp` commands for each backup
- ExecuteRollback: iterate Steps in reverse, run each action, verify

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 4: Hardener Engine — Approval Workflow

**Files:**
- Create: `defense-kit-cli/internal/hardener/engine.go`
- Modify: `defense-kit-cli/internal/hardener/hardener_test.go`

- [ ] **Step 1: Write failing tests**

Test: DryRun mode shows plans but doesn't apply, engine processes fixable findings, engine skips non-fixable, engine stops on failure, engine generates rollback.

- [ ] **Step 2: Implement engine.go**

```go
type Engine struct {
    registry  *HardenerRegistry
    outputDir string
}

type HardenResult struct {
    Finding   scanner.Finding
    Plan      FixPlan
    Applied   bool
    Verified  bool
    Error     string
}

func NewEngine(registry *HardenerRegistry, outputDir string) *Engine
func (e *Engine) Run(ctx context.Context, findings []scanner.Finding, opts HardenOptions) ([]HardenResult, error)
```

Run workflow:
1. Filter to fixable findings via registry
2. For each fixable finding:
   a. Get hardener via registry.FindHardener
   b. Preview: get FixPlan
   c. Check approval mode (dry-run → print plan, skip apply)
   d. Backup files listed in plan
   e. Apply via hardener.Apply
   f. Verify via hardener.Verify
   g. If verify fails → auto-rollback that fix
   h. If apply fails → stop, report
   i. Record result
3. Generate rollback script for all applied fixes
4. Return results

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 5: SSH Hardener — First Real Implementation

**Files:**
- Create: `defense-kit-cli/internal/hardener/ssh.go`
- Create: `defense-kit-cli/internal/hardener/ssh_test.go`

- [ ] **Step 1: Write failing tests**

Test with temp sshd_config file: CanFix returns true for SSH findings, Preview shows correct plan, Apply modifies config, Verify checks config, Rollback restores original.

- [ ] **Step 2: Implement ssh.go**

```go
type SSHHardener struct {
    configPath string // default: /etc/ssh/sshd_config
}

func NewSSHHardener() *SSHHardener
```

CanFix: returns true for findings from scanner "ssh" with known fixable titles.

Fixes:
- PermitRootLogin yes → no
- PasswordAuthentication yes → no
- PermitEmptyPasswords yes → no
- MaxAuthTries > 6 → 3

Apply: read sshd_config, replace directive value, write back.
Verify: re-read config, check directive has new value.
Rollback: restore from backup.

Uses `FixAction{Type: FileEdit, Target: "/etc/ssh/sshd_config"}` — no shell.

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 6: OS + Firewall + Git Hardeners (stubs with structure)

**Files:**
- Create: `defense-kit-cli/internal/hardener/os.go` — sysctl hardener stub
- Create: `defense-kit-cli/internal/hardener/firewall.go` — ufw hardener stub
- Create: `defense-kit-cli/internal/hardener/git.go` — git config hardener stub

Each implements Hardener interface with CanFix returning false (no fixes yet), Apply/Verify/Rollback returning nil. These will be filled in later.

- [ ] **Step 1: Create stubs**

- [ ] **Step 2: Run tests — pass**

- [ ] **Step 3: Commit**

---

### Task 7: Wire Harden Command to CLI

**Files:**
- Modify: `defense-kit-cli/cmd/defense-kit/main.go`

- [ ] **Step 1: Add harden command**

```go
hardenCmd := &cobra.Command{
    Use:   "harden",
    Short: "Fix security issues (requires approval)",
    RunE:  runHarden,
}
hardenCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show fixes without applying")
hardenCmd.Flags().StringVar(&approvalMode, "mode", "interactive", "approval mode: interactive, batch, auto-low, dry-run")
```

- [ ] **Step 2: Implement runHarden**

1. Run full scan first (get findings)
2. Create HardenerRegistry, register SSH hardener
3. Create hardener Engine
4. Filter to fixable findings
5. Run engine with approval mode
6. Print results (what was fixed, what was skipped)
7. Print rollback script location

- [ ] **Step 3: Build and test**

```bash
make build
./bin/defense-kit harden --dry-run  # should show fixable findings without applying
```

- [ ] **Step 4: Commit**

---

### Task 8: E2E Verification

- [ ] **Step 1: Dry run shows plans**

Run: `./bin/defense-kit harden --dry-run`
Expected: Shows fixable findings with planned changes

- [ ] **Step 2: Full test suite**

Run: `go test ./... -race`
Expected: All pass

- [ ] **Step 3: Final commit**
