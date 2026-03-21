package monitor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/baseline"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/monitor"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ---------------------------------------------------------------------------
// Test scanner implementations
// ---------------------------------------------------------------------------

// fixedScanner returns a predetermined set of findings.
type fixedScanner struct {
	name     string
	category string
	findings []scanner.Finding
}

func (f *fixedScanner) Name() string             { return f.name }
func (f *fixedScanner) Category() string         { return f.category }
func (f *fixedScanner) Description() string      { return "fixed scanner: " + f.name }
func (f *fixedScanner) RequiredTools() []string  { return nil }
func (f *fixedScanner) OptionalTools() []string  { return nil }
func (f *fixedScanner) RequiresRoot() bool       { return false }
func (f *fixedScanner) Available() bool          { return true }
func (f *fixedScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return f.findings, nil
}

// quickFlagCapturingScanner captures the Quick flag value for assertion.
type quickFlagCapturingScanner struct {
	name         string
	category     string
	capturedOpts *scanner.ScanOptions
}

func (q *quickFlagCapturingScanner) Name() string             { return q.name }
func (q *quickFlagCapturingScanner) Category() string         { return q.category }
func (q *quickFlagCapturingScanner) Description() string      { return "capturing scanner: " + q.name }
func (q *quickFlagCapturingScanner) RequiredTools() []string  { return nil }
func (q *quickFlagCapturingScanner) OptionalTools() []string  { return nil }
func (q *quickFlagCapturingScanner) RequiresRoot() bool       { return false }
func (q *quickFlagCapturingScanner) Available() bool          { return true }
func (q *quickFlagCapturingScanner) Scan(_ context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	*q.capturedOpts = opts
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeFindings(ids ...string) []scanner.Finding {
	findings := make([]scanner.Finding, 0, len(ids))
	for _, id := range ids {
		findings = append(findings, scanner.Finding{
			ID:       id,
			Scanner:  "test-scanner",
			Severity: scanner.SevMedium,
			Title:    "Finding " + id,
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestMonitor_FirstRunCreatesBaseline verifies that when no baseline file
// exists, Monitor.Run saves current findings as the new baseline and returns
// IsFirstRun=true with an empty Diff.
func TestMonitor_FirstRunCreatesBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	outputDir := filepath.Join(dir, "output")

	findings := makeFindings("finding-001", "finding-002")

	reg := scanner.NewRegistry()
	reg.Register(&fixedScanner{
		name:     "test-scanner",
		category: "test",
		findings: findings,
	})

	m := monitor.New(reg, baselinePath, outputDir)

	opts := scanner.ScanOptions{
		Timeout: 5 * time.Second,
	}

	result, err := m.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IsFirstRun must be true.
	if !result.IsFirstRun {
		t.Error("expected IsFirstRun=true on first run, got false")
	}

	// Diff should be empty (no previous baseline to compare against).
	if len(result.Diff.New) != 0 {
		t.Errorf("expected 0 new findings in diff, got %d", len(result.Diff.New))
	}
	if len(result.Diff.Resolved) != 0 {
		t.Errorf("expected 0 resolved findings in diff, got %d", len(result.Diff.Resolved))
	}

	// AllFindings must contain the findings returned by the scanner.
	if len(result.AllFindings) != 2 {
		t.Errorf("expected 2 all-findings, got %d", len(result.AllFindings))
	}

	// BaselinePath must be set correctly.
	if result.BaselinePath != baselinePath {
		t.Errorf("expected BaselinePath=%q, got %q", baselinePath, result.BaselinePath)
	}

	// Baseline file must have been created on disk.
	if _, statErr := os.Stat(baselinePath); os.IsNotExist(statErr) {
		t.Error("expected baseline file to be created, but it does not exist")
	}

	// Load the saved baseline and verify it contains the current findings.
	saved, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("failed to load saved baseline: %v", err)
	}
	if len(saved.Findings) != 2 {
		t.Errorf("expected 2 findings in saved baseline, got %d", len(saved.Findings))
	}
}

// TestMonitor_DiffAgainstBaseline verifies that when a baseline already
// exists, Monitor.Run computes the diff and does NOT set IsFirstRun.
func TestMonitor_DiffAgainstBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	outputDir := filepath.Join(dir, "output")

	// Pre-save a baseline with 2 findings.
	oldFindings := makeFindings("finding-001", "finding-002")
	if err := baseline.Save(baselinePath, baseline.Baseline{
		Findings: oldFindings,
	}); err != nil {
		t.Fatalf("failed to save initial baseline: %v", err)
	}

	// Scanner now returns finding-001 (unchanged) and finding-003 (new).
	// finding-002 is no longer present → resolved.
	newFindings := makeFindings("finding-001", "finding-003")

	reg := scanner.NewRegistry()
	reg.Register(&fixedScanner{
		name:     "test-scanner",
		category: "test",
		findings: newFindings,
	})

	m := monitor.New(reg, baselinePath, outputDir)

	opts := scanner.ScanOptions{
		Timeout: 5 * time.Second,
	}

	result, err := m.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Not a first run.
	if result.IsFirstRun {
		t.Error("expected IsFirstRun=false when baseline already exists")
	}

	// Expect 1 new finding (finding-003).
	if len(result.Diff.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(result.Diff.New))
	} else if result.Diff.New[0].ID != "finding-003" {
		t.Errorf("expected new finding ID=finding-003, got %q", result.Diff.New[0].ID)
	}

	// Expect 1 resolved finding (finding-002).
	if len(result.Diff.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(result.Diff.Resolved))
	} else if result.Diff.Resolved[0].ID != "finding-002" {
		t.Errorf("expected resolved finding ID=finding-002, got %q", result.Diff.Resolved[0].ID)
	}

	// Expect 1 unchanged finding (finding-001).
	if len(result.Diff.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", len(result.Diff.Unchanged))
	}

	// AllFindings must contain the current scan's 2 findings.
	if len(result.AllFindings) != 2 {
		t.Errorf("expected 2 all-findings, got %d", len(result.AllFindings))
	}
}

// TestMonitor_QuickModeForced verifies that Monitor.Run always forces
// opts.Quick=true regardless of what the caller passes.
func TestMonitor_QuickModeForced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	outputDir := filepath.Join(dir, "output")

	captured := &scanner.ScanOptions{}
	capturer := &quickFlagCapturingScanner{
		name:         "capturer",
		category:     "test",
		capturedOpts: captured,
	}

	reg := scanner.NewRegistry()
	reg.Register(capturer)

	m := monitor.New(reg, baselinePath, outputDir)

	// Deliberately pass Quick=false to verify it gets forced to true.
	opts := scanner.ScanOptions{
		Quick:   false,
		Timeout: 5 * time.Second,
	}

	_, err := m.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !captured.Quick {
		t.Error("expected opts.Quick to be forced to true inside Monitor.Run")
	}
}

// TestMonitor_OutputDirCreated verifies that the JSON report is written to
// the output directory even when that directory does not exist yet.
func TestMonitor_OutputDirCreated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	// Use a nested outputDir that doesn't exist yet.
	outputDir := filepath.Join(dir, "nested", "output")

	reg := scanner.NewRegistry()
	reg.Register(&fixedScanner{
		name:     "test-scanner",
		category: "test",
		findings: makeFindings("finding-001"),
	})

	m := monitor.New(reg, baselinePath, outputDir)

	opts := scanner.ScanOptions{
		Timeout: 5 * time.Second,
	}

	_, err := m.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that at least one file was written inside outputDir.
	entries, readErr := os.ReadDir(outputDir)
	if readErr != nil {
		t.Fatalf("expected outputDir to be created, but ReadDir failed: %v", readErr)
	}
	if len(entries) == 0 {
		t.Error("expected at least one entry in outputDir after run")
	}
}
