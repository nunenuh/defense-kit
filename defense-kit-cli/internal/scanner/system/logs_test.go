package system_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/system"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newLogsScanner creates a LogsScanner with its procPath set to fakeProcDir
// so tests do not depend on the real /proc directory.
func newLogsScanner(fakeProcDir string) *system.LogsScanner {
	s := system.NewLogsScanner()
	s.SetProcPath(fakeProcDir)
	return s
}

// writeTempLog writes content to a new temp file and returns its path.
func writeTempLog(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "auth*.log")
	if err != nil {
		t.Fatalf("creating temp log: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp log: %v", err)
	}
	f.Close()
	return f.Name()
}

// makeFakeProc creates a minimal /proc-like directory containing a single
// process whose comm file contains the provided name.
func makeFakeProc(t *testing.T, commName string) string {
	t.Helper()
	dir := t.TempDir()
	pidDir := filepath.Join(dir, "1234")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("creating fake pid dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(commName+"\n"), 0644); err != nil {
		t.Fatalf("writing fake comm: %v", err)
	}
	return dir
}

// hasFindingWithSubstring returns true when at least one finding's Detail or
// Title contains substr (case-insensitive).
func hasFindingWithSubstring(findings []scanner.Finding, substr string) bool {
	lower := strings.ToLower(substr)
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Detail), lower) ||
			strings.Contains(strings.ToLower(f.Title), lower) {
			return true
		}
	}
	return false
}

// hasFindingWithSeverity returns true when at least one finding has the given severity.
func hasFindingWithSeverity(findings []scanner.Finding, sev scanner.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Test: empty log file → CRITICAL finding
// ---------------------------------------------------------------------------

func TestLogsScanner_EmptyLogFile_CriticalFinding(t *testing.T) {
	// Create an empty temp file and point a custom scanner at it via a fake
	// /proc that has a valid logging service (so we don't also get a
	// "no logging service" finding that could obscure our assertion).
	fakeProc := makeFakeProc(t, "rsyslogd")
	s := newLogsScanner(fakeProc)

	// Patch the candidate paths to use our temp empty file.
	tmpDir := t.TempDir()
	emptyPath := filepath.Join(tmpDir, "auth.log")
	if err := os.WriteFile(emptyPath, []byte{}, 0640); err != nil {
		t.Fatalf("creating empty log: %v", err)
	}

	s.SetAuthLogPath(emptyPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasFindingWithSubstring(findings, "empty") {
		t.Errorf("expected a CRITICAL finding about empty log, got %d findings: %+v", len(findings), findings)
	}
	if !hasFindingWithSeverity(findings, scanner.SevCritical) {
		t.Errorf("expected at least one CRITICAL severity finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Test: timestamp gap > 1 hour → HIGH finding
// ---------------------------------------------------------------------------

func TestLogsScanner_TimestampGap_HighFinding(t *testing.T) {
	fakeProc := makeFakeProc(t, "rsyslogd")
	s := newLogsScanner(fakeProc)

	// Build a log file where there is a 2-hour gap between entries.
	now := time.Now()
	earlyTime := now.Add(-3 * time.Hour)
	lateTime := now.Add(-1 * time.Hour) // 2-hour gap after earlyTime

	formatSyslog := func(t time.Time, msg string) string {
		// syslog format: "Jan  2 15:04:05 hostname msg"
		return t.Format("Jan _2 15:04:05") + " testhost " + msg
	}

	content := formatSyslog(earlyTime, "session opened for user root") + "\n" +
		formatSyslog(lateTime, "session opened for user alice") + "\n"

	logPath := writeTempLog(t, content)
	s.SetAuthLogPath(logPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasFindingWithSubstring(findings, "gap") {
		t.Errorf("expected a HIGH finding about timestamp gap, got %d findings: %+v", len(findings), findings)
	}
	if !hasFindingWithSeverity(findings, scanner.SevHigh) {
		t.Errorf("expected at least one HIGH severity finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Test: 100 "Failed password" lines → brute-force finding
// ---------------------------------------------------------------------------

func TestLogsScanner_BruteForce_MediumFinding(t *testing.T) {
	fakeProc := makeFakeProc(t, "rsyslogd")
	s := newLogsScanner(fakeProc)

	now := time.Now()
	var lines []string
	for i := 0; i < 100; i++ {
		ts := now.Add(time.Duration(-100+i) * time.Minute)
		lines = append(lines, ts.Format("Jan _2 15:04:05")+" testhost sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 12345 ssh2")
	}
	content := strings.Join(lines, "\n") + "\n"

	logPath := writeTempLog(t, content)
	s.SetAuthLogPath(logPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasFindingWithSubstring(findings, "brute force") && !hasFindingWithSubstring(findings, "failed login") {
		t.Errorf("expected a brute-force finding, got %d findings: %+v", len(findings), findings)
	}
	// 100 failures → MEDIUM (> 50)
	hasMediumOrHigher := false
	for _, f := range findings {
		if f.Severity >= scanner.SevMedium {
			hasMediumOrHigher = true
			break
		}
	}
	if !hasMediumOrHigher {
		t.Errorf("expected at least MEDIUM severity finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Test: >200 failures → HIGH finding
// ---------------------------------------------------------------------------

func TestLogsScanner_BruteForce_HighFinding(t *testing.T) {
	fakeProc := makeFakeProc(t, "rsyslogd")
	s := newLogsScanner(fakeProc)

	now := time.Now()
	var lines []string
	for i := 0; i < 250; i++ {
		ts := now.Add(time.Duration(-250+i) * time.Second)
		lines = append(lines, ts.Format("Jan _2 15:04:05")+" testhost sshd[999]: Failed password for root from 192.168.1.1 port 22 ssh2")
	}
	content := strings.Join(lines, "\n") + "\n"

	logPath := writeTempLog(t, content)
	s.SetAuthLogPath(logPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasFindingWithSeverity(findings, scanner.SevHigh) {
		t.Errorf("expected a HIGH severity brute-force finding for 250 failures, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Test: no logging service → HIGH finding
// ---------------------------------------------------------------------------

func TestLogsScanner_NoLoggingService_HighFinding(t *testing.T) {
	// Create a fake /proc with an irrelevant process.
	fakeProc := makeFakeProc(t, "bash")
	s := newLogsScanner(fakeProc)

	// Provide a valid non-empty log so that doesn't distort results.
	now := time.Now()
	line := fmt.Sprintf("%s testhost sshd[1]: Accepted publickey for alice\n", now.Format("Jan _2 15:04:05"))
	logPath := writeTempLog(t, line)
	s.SetAuthLogPath(logPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasFindingWithSubstring(findings, "logging service") {
		t.Errorf("expected a finding about missing logging service, got %d findings: %+v", len(findings), findings)
	}
	if !hasFindingWithSeverity(findings, scanner.SevHigh) {
		t.Errorf("expected HIGH severity for missing logging service: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Test: interface compliance (compile-time)
// ---------------------------------------------------------------------------

func TestLogsScanner_InterfaceCompliance(t *testing.T) {
	// This is a compile-time assertion — if LogsScanner doesn't satisfy
	// scanner.Scanner, the test file will fail to compile.
	var _ scanner.Scanner = (*system.LogsScanner)(nil)
}

// ---------------------------------------------------------------------------
// Test: clean log produces no findings
// ---------------------------------------------------------------------------

func TestLogsScanner_CleanLog_NoFindings(t *testing.T) {
	fakeProc := makeFakeProc(t, "rsyslogd")
	s := newLogsScanner(fakeProc)

	now := time.Now()
	var lines []string
	for i := 0; i < 10; i++ {
		ts := now.Add(time.Duration(-10+i) * time.Minute)
		lines = append(lines, ts.Format("Jan _2 15:04:05")+" testhost sshd[1]: Accepted publickey for alice")
	}
	content := strings.Join(lines, "\n") + "\n"

	logPath := writeTempLog(t, content)

	// Make the file 0640 so permissions check passes.
	if err := os.Chmod(logPath, 0640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	s.SetAuthLogPath(logPath)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Only unexpected (non-syslog) findings would be a problem.
	// We allow zero findings on a clean log.
	for _, f := range findings {
		if f.Severity >= scanner.SevHigh {
			t.Errorf("unexpected HIGH+ finding on clean log: %+v", f)
		}
	}
}
