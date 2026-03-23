package process_test

import (
	"context"
	"os"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/process"
)

// ---- SuspiciousScanner interface tests ----

func TestSuspiciousScanner_Interface(t *testing.T) {
	s := process.NewSuspiciousScanner()

	if s.Name() != "processes" {
		t.Errorf("Name() = %q, want %q", s.Name(), "processes")
	}
	if s.Category() != "process" {
		t.Errorf("Category() = %q, want %q", s.Category(), "process")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should be nil")
	}
	if s.OptionalTools() != nil {
		t.Error("OptionalTools() should be nil")
	}
}

// ---- MemoryScanner interface tests ----

func TestMemoryScanner_Interface(t *testing.T) {
	s := process.NewMemoryScanner()

	if s.Name() != "memory" {
		t.Errorf("Name() = %q, want %q", s.Name(), "memory")
	}
	if s.Category() != "process" {
		t.Errorf("Category() = %q, want %q", s.Category(), "process")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// ---- ClipboardScanner interface tests ----

func TestClipboardScanner_Interface(t *testing.T) {
	s := process.NewClipboardScanner()

	if s.Name() != "clipboard" {
		t.Errorf("Name() = %q, want %q", s.Name(), "clipboard")
	}
	if s.Category() != "process" {
		t.Errorf("Category() = %q, want %q", s.Category(), "process")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// ---- SuspiciousScanner functional tests ----

func TestSuspiciousScanner_Scan_DoesNotError(t *testing.T) {
	// Scan against the real /proc — should never return a hard error.
	s := process.NewSuspiciousScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

func TestSuspiciousScanner_FindingFields(t *testing.T) {
	// Run against the real /proc and validate that any returned findings are
	// properly populated. In most CI environments no findings will be returned
	// (no miners / reverse shells running), but if they are the fields must be valid.
	s := process.NewSuspiciousScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "processes" {
			t.Errorf("Scanner = %q, want %q", f.Scanner, "processes")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
		if f.Location == "" {
			t.Error("finding has empty Location")
		}
		if f.Metadata == nil {
			t.Error("finding has nil Metadata")
		}
		if _, ok := f.Metadata["pid"]; !ok {
			t.Error("finding Metadata missing 'pid' key")
		}
	}
}

// ---- MemoryScanner functional tests ----

func TestMemoryScanner_ScanDoesNotError(t *testing.T) {
	s := process.NewMemoryScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

func TestMemoryScanner_FindingFields(t *testing.T) {
	// Run against the real /proc and validate that any returned findings have
	// all required fields populated. Most CI environments will have no findings.
	s := process.NewMemoryScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "memory" {
			t.Errorf("Scanner = %q, want %q", f.Scanner, "memory")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
		if f.Location == "" {
			t.Error("finding has empty Location")
		}
	}
}

// TestMemoryScanner_DetectsDeletedExe verifies that the scanner flags a process
// whose /proc/<pid>/exe symlink contains "(deleted)".
func TestMemoryScanner_DetectsDeletedExe(t *testing.T) {
	dir := t.TempDir()
	// Construct a fake /proc tree:
	//   <dir>/proc/1234/exe -> /tmp/malware (deleted)
	pidDir := dir + "/proc/1234"
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create a real file so os.Symlink has a valid target, then make a
	// symlink whose target text contains "(deleted)" to simulate the kernel's
	// behaviour. On Linux, os.Readlink returns the raw symlink target text
	// regardless of whether the target exists.
	exeLink := pidDir + "/exe"
	if err := os.Symlink("/tmp/malware (deleted)", exeLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	s := process.NewMemoryScannerWithRoot(dir + "/proc")
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "memory" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL finding for deleted exe, got: %+v", findings)
	}
}

func TestClipboardScanner_ScanReturnsNil(t *testing.T) {
	s := process.NewClipboardScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings from stub, got %v", findings)
	}
}
