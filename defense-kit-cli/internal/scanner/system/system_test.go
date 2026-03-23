package system_test

import (
	"context"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/system"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultOpts() scanner.ScanOptions {
	return scanner.ScanOptions{}
}

// verifyInterfaceCompliance is a compile-time check that all system scanners
// satisfy the scanner.Scanner interface.
func verifyInterfaceCompliance() {
	var _ scanner.Scanner = (*system.RootkitScanner)(nil)
	var _ scanner.Scanner = (*system.BootScanner)(nil)
	var _ scanner.Scanner = (*system.LogsScanner)(nil)
	var _ scanner.Scanner = (*system.PackageMgrScanner)(nil)
}

// ---------------------------------------------------------------------------
// RootkitScanner — interface tests
// ---------------------------------------------------------------------------

func TestRootkitScanner_Interface(t *testing.T) {
	s := system.NewRootkitScanner()

	if got := s.Name(); got != "rootkit" {
		t.Errorf("Name() = %q, want %q", got, "rootkit")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
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
	if s.RequiredTools() != nil {
		t.Errorf("RequiredTools() = %v, want nil", s.RequiredTools())
	}
}

// TestRootkitScanner_Scan_DoesNotPanic verifies that Scan completes without
// panicking on a real host. We cannot reliably mock /proc/modules, so we only
// assert that the call returns without error or panic. Findings may or may not
// be present depending on the host environment.
func TestRootkitScanner_Scan_DoesNotPanic(t *testing.T) {
	s := system.NewRootkitScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	// err may be non-nil when running without root; that is acceptable.
	// We only care that nothing panicked and that any returned findings have
	// the required fields populated.
	if err != nil {
		t.Logf("Scan returned error (may be expected without root): %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding has empty ID: %+v", f)
		}
		if f.Scanner == "" {
			t.Errorf("finding has empty Scanner: %+v", f)
		}
		if f.Title == "" {
			t.Errorf("finding has empty Title: %+v", f)
		}
		if f.Severity < scanner.SevLow || f.Severity > scanner.SevCritical {
			t.Errorf("finding has invalid Severity %d: %+v", f.Severity, f)
		}
	}
}

// ---------------------------------------------------------------------------
// BootScanner — interface tests
// ---------------------------------------------------------------------------

func TestBootScanner_Interface(t *testing.T) {
	s := system.NewBootScanner()

	if got := s.Name(); got != "boot" {
		t.Errorf("Name() = %q, want %q", got, "boot")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
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

func TestBootScanner_StubReturnsNoFindings(t *testing.T) {
	s := system.NewBootScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("stub Scan should return 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// LogsScanner — interface tests
// ---------------------------------------------------------------------------

func TestLogsScanner_Interface(t *testing.T) {
	s := system.NewLogsScanner()

	if got := s.Name(); got != "logs" {
		t.Errorf("Name() = %q, want %q", got, "logs")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
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

func TestLogsScanner_Scan_DoesNotPanic(t *testing.T) {
	s := system.NewLogsScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	// err is acceptable (e.g., no /var/log/auth.log on this host).
	if err != nil {
		t.Logf("Scan returned error (may be expected in test environment): %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding has empty ID: %+v", f)
		}
		if f.Scanner == "" {
			t.Errorf("finding has empty Scanner: %+v", f)
		}
		if f.Title == "" {
			t.Errorf("finding has empty Title: %+v", f)
		}
		if f.Severity < scanner.SevLow || f.Severity > scanner.SevCritical {
			t.Errorf("finding has invalid Severity %d: %+v", f.Severity, f)
		}
	}
}

// ---------------------------------------------------------------------------
// PackageMgrScanner — interface tests
// ---------------------------------------------------------------------------

func TestPackageMgrScanner_Interface(t *testing.T) {
	s := system.NewPackageMgrScanner()

	if got := s.Name(); got != "package_manager" {
		t.Errorf("Name() = %q, want %q", got, "package_manager")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
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

func TestPackageMgrScanner_StubReturnsNoFindings(t *testing.T) {
	s := system.NewPackageMgrScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("stub Scan should return 0 findings, got %d", len(findings))
	}
}
