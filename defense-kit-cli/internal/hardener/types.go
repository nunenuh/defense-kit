package hardener

import (
	"context"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ActionType describes the kind of operation a FixAction performs.
type ActionType int

const (
	FileEdit      ActionType = iota // 0
	FileCreate                      // 1
	FileDelete                      // 2
	ServiceRestart                  // 3
	CommandExec                     // 4
)

// String returns the human-readable name of the ActionType.
func (a ActionType) String() string {
	switch a {
	case FileEdit:
		return "FileEdit"
	case FileCreate:
		return "FileCreate"
	case FileDelete:
		return "FileDelete"
	case ServiceRestart:
		return "ServiceRestart"
	case CommandExec:
		return "CommandExec"
	default:
		return "Unknown"
	}
}

// ApprovalMode controls how user approval is obtained before applying fixes.
type ApprovalMode int

const (
	ModeInteractive ApprovalMode = iota // 0 – prompt for each fix
	ModeBatch                           // 1 – prompt once for all fixes
	ModeAutoLow                         // 2 – auto-approve LOW severity fixes
	ModeDryRun                          // 3 – preview only, no changes applied
)

// String returns the human-readable name of the ApprovalMode.
func (m ApprovalMode) String() string {
	switch m {
	case ModeInteractive:
		return "Interactive"
	case ModeBatch:
		return "Batch"
	case ModeAutoLow:
		return "AutoLow"
	case ModeDryRun:
		return "DryRun"
	default:
		return "Unknown"
	}
}

// FixAction is a single, atomic operation that a hardener executes.
type FixAction struct {
	Type       ActionType // kind of action
	Target     string     // file path or service name
	Args       []string   // explicit argv passed to the operation
	Validation []string   // argv used to verify success after execution
}

// FixPlan groups all the information needed to apply and roll back a fix for
// a single Finding.
type FixPlan struct {
	Finding     scanner.Finding
	Description string
	Actions     []FixAction
	BackupPaths map[string]string // original path → backup path
	Rollback    RollbackPlan
}

// RollbackStep describes one undo operation within a RollbackPlan.
type RollbackStep struct {
	Description string
	Action      FixAction
	Verify      []string // argv to confirm the rollback succeeded
	BackupPath  string   // path of the file backup to restore
}

// RollbackPlan holds the full sequence of steps required to undo a fix session.
type RollbackPlan struct {
	SessionID string
	Timestamp time.Time
	Steps     []RollbackStep
}

// Hardener is implemented by every module that can remediate a Finding.
type Hardener interface {
	// Name returns the unique identifier of this hardener.
	Name() string
	// CanFix reports whether this hardener knows how to remediate f.
	CanFix(finding scanner.Finding) bool
	// Preview builds a FixPlan without applying any changes.
	Preview(finding scanner.Finding) FixPlan
	// Apply executes plan against the live system.
	Apply(ctx context.Context, plan FixPlan) error
	// Verify checks that the fix was successful.
	Verify(ctx context.Context, plan FixPlan) error
	// Rollback undoes the changes described by plan.
	Rollback(ctx context.Context, plan FixPlan) error
}

// HardenOptions configures a hardening run.
type HardenOptions struct {
	Mode      ApprovalMode
	OutputDir string
	Findings  []scanner.Finding
	DryRun    bool
}

// HardenResult records the outcome of applying a single FixPlan.
type HardenResult struct {
	Finding  scanner.Finding
	Plan     FixPlan
	Applied  bool
	Verified bool
	Error    string
}
