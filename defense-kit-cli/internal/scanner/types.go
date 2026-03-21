package scanner

import (
	"context"
	"time"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SevLow      Severity = iota // 0
	SevMedium                   // 1
	SevHigh                     // 2
	SevCritical                 // 3
)

// String returns the uppercase string representation of a Severity.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Finding represents a single security finding produced by a scanner.
type Finding struct {
	ID          string            `json:"id"`
	Scanner     string            `json:"scanner"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Detail      string            `json:"detail"`
	Evidence    string            `json:"evidence"`
	Location    string            `json:"location"`
	Remediation string            `json:"remediation"`
	CanAutoFix  bool              `json:"can_auto_fix"`
	References  []string          `json:"references"`
	Metadata    map[string]string `json:"metadata"`
}

// ScanStatus represents the outcome status of a scan.
type ScanStatus int

const (
	ScanSuccess ScanStatus = iota // 0
	ScanPartial                   // 1
	ScanFailed                    // 2
	ScanSkipped                   // 3
)

// String returns the lowercase string representation of a ScanStatus.
func (s ScanStatus) String() string {
	switch s {
	case ScanSuccess:
		return "success"
	case ScanPartial:
		return "partial"
	case ScanFailed:
		return "failed"
	case ScanSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// ScanResult holds the outcome of running a single scanner.
type ScanResult struct {
	Scanner  string        `json:"scanner"`
	Status   ScanStatus    `json:"status"`
	Findings []Finding     `json:"findings"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// ScanOptions configures how scanners operate.
type ScanOptions struct {
	TargetPaths      []string
	ExcludePaths     []string
	Categories       []string
	QuickCategories  []string
	Timeout          time.Duration
	Concurrency      int
	UseExtTools      bool
	PolicyPath       string
	Quick            bool
	Diff             bool
	Verbose          bool
}

// Scanner is the interface that all defensive security scanners must implement.
type Scanner interface {
	// Name returns the unique identifier of the scanner.
	Name() string
	// Category returns the logical grouping of the scanner (e.g., "secrets", "network").
	Category() string
	// Description returns a human-readable explanation of what the scanner checks.
	Description() string
	// Scan runs the scanner against the provided options and returns findings.
	Scan(ctx context.Context, opts ScanOptions) ([]Finding, error)
	// RequiredTools lists external binaries that must be present for the scanner to work.
	RequiredTools() []string
	// OptionalTools lists external binaries that enhance but are not required for scanning.
	OptionalTools() []string
	// RequiresRoot reports whether the scanner needs root / elevated privileges.
	RequiresRoot() bool
	// Available reports whether the scanner can run in the current environment.
	Available() bool
}
