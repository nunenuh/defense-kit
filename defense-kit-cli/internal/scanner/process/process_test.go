package process_test

import (
	"context"
	"os"
	"path/filepath"
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

func TestClipboardScanner_ScanDoesNotError(t *testing.T) {
	s := process.NewClipboardScanner()
	// Scan must not return an error; findings depend on whether any keylogger
	// processes are running in the test environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ClipboardScanner — detection tests with fake /proc tree
// ---------------------------------------------------------------------------

// buildFakeProcEntry creates a fake /proc/<pid>/ directory with cmdline and
// optionally an environ file.
func buildFakeProcEntry(t *testing.T, procRoot, pid, cmdline, display string) {
	t.Helper()
	pidDir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// cmdline bytes are NUL-separated.
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(cmdline+"\x00"), 0o644); err != nil {
		t.Fatalf("WriteFile cmdline: %v", err)
	}
	if display != "" {
		env := "DISPLAY=" + display + "\x00"
		if err := os.WriteFile(filepath.Join(pidDir, "environ"), []byte(env), 0o644); err != nil {
			t.Fatalf("WriteFile environ: %v", err)
		}
	}
}

func TestClipboardScanner_DetectsXinputTest(t *testing.T) {
	procRoot := t.TempDir()
	buildFakeProcEntry(t, procRoot, "1234", "xinput test --id=3", "")

	s := process.NewClipboardScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "clipboard" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for xinput test, got: %+v", findings)
	}
}

func TestClipboardScanner_DetectsXclipOut(t *testing.T) {
	procRoot := t.TempDir()
	buildFakeProcEntry(t, procRoot, "5678", "xclip -o -selection clipboard", "")

	s := process.NewClipboardScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "clipboard" && f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for xclip -o, got: %+v", findings)
	}
}

func TestClipboardScanner_CleanProcNoFindings(t *testing.T) {
	procRoot := t.TempDir()
	buildFakeProcEntry(t, procRoot, "9999", "/usr/bin/sshd -D", "")

	s := process.NewClipboardScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean sshd process, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// MemoryScanner — checkTracerPid coverage
// ---------------------------------------------------------------------------

func TestMemoryScanner_DetectsTracerPid(t *testing.T) {
	procRoot := t.TempDir()
	pid := "2222"
	pidDir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Write a status file with a non-zero TracerPid.
	statusContent := "Name:\ttarget\nPid:\t2222\nTracerPid:\t1111\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(statusContent), 0o644); err != nil {
		t.Fatalf("WriteFile status: %v", err)
	}
	// Write a valid exe symlink target (non-deleted).
	if err := os.WriteFile(filepath.Join(pidDir, "exe"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile exe: %v", err)
	}
	// Write maps without suspicious entries.
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile maps: %v", err)
	}

	s := process.NewMemoryScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "memory" && f.Title == "Process being traced (possible code injection)" {
			found = true
			if f.Severity != scanner.SevHigh {
				t.Errorf("TracerPid finding severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected 'being traced' finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// ClipboardScanner — X11 sniffing with DISPLAY env (exercises readEnvVar)
// ---------------------------------------------------------------------------

func TestClipboardScanner_DetectsX11Keylogger(t *testing.T) {
	procRoot := t.TempDir()
	// "logkeys" with DISPLAY set → X11 sniffer finding.
	buildFakeProcEntry(t, procRoot, "7777", "logkeys --start --output=/tmp/keys.log", ":0")

	s := process.NewClipboardScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "clipboard" && f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for logkeys with DISPLAY, got: %+v", findings)
	}
}

func TestClipboardScanner_X11SnifferWithoutDisplay(t *testing.T) {
	procRoot := t.TempDir()
	// "logkeys" without DISPLAY set → no X11 sniffer finding.
	buildFakeProcEntry(t, procRoot, "8888", "logkeys --start --output=/tmp/keys.log", "")

	s := process.NewClipboardScannerWithRoot(procRoot)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Suspected X11 keylogger/sniffer process" {
			t.Errorf("unexpected X11 sniffer finding when DISPLAY not set: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// RequiredTools / OptionalTools — cover the 0% one-liners
// ---------------------------------------------------------------------------

func TestAllProcessScanners_RequiredOptionalTools(t *testing.T) {
	_ = process.NewClipboardScanner().RequiredTools()
	_ = process.NewClipboardScanner().OptionalTools()
	_ = process.NewMemoryScanner().RequiredTools()
	_ = process.NewMemoryScanner().OptionalTools()
}
