package reporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// helpers

func makeFinding(sev scanner.Severity, title, location, detail, evidence, remediation string) scanner.Finding {
	return scanner.Finding{
		ID:          "test-id",
		Scanner:     "test-scanner",
		Severity:    sev,
		Title:       title,
		Location:    location,
		Detail:      detail,
		Evidence:    evidence,
		Remediation: remediation,
	}
}

func makeResults(findings ...scanner.Finding) []scanner.ScanResult {
	return []scanner.ScanResult{
		{
			Scanner:  "test-scanner",
			Status:   scanner.ScanSuccess,
			Findings: findings,
		},
	}
}

// --- TerminalReporter tests ---

func TestTerminalReporterRender(t *testing.T) {
	criticalFinding := makeFinding(scanner.SevCritical, "Root SSH Enabled", "/etc/ssh/sshd_config", "PermitRootLogin yes", "PermitRootLogin yes", "Set PermitRootLogin no")
	mediumFinding := makeFinding(scanner.SevMedium, "Weak Cipher Used", "/etc/ssl/openssl.cnf", "RC4 cipher detected", "SSLCipherSuite RC4", "Replace with AES-256")

	results := makeResults(criticalFinding, mediumFinding)

	var buf bytes.Buffer
	tr := reporter.NewTerminalReporter(&buf)
	tr.Render(results)

	output := buf.String()

	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("expected output to contain CRITICAL, got:\n%s", output)
	}
	if !strings.Contains(output, "Root SSH Enabled") {
		t.Errorf("expected output to contain finding title 'Root SSH Enabled', got:\n%s", output)
	}
	if !strings.Contains(output, "MEDIUM") {
		t.Errorf("expected output to contain MEDIUM, got:\n%s", output)
	}
	if !strings.Contains(output, "Weak Cipher Used") {
		t.Errorf("expected output to contain finding title 'Weak Cipher Used', got:\n%s", output)
	}
	if !strings.Contains(output, "/etc/ssh/sshd_config") {
		t.Errorf("expected output to contain location '/etc/ssh/sshd_config', got:\n%s", output)
	}
	if !strings.Contains(output, "SCAN COMPLETE") {
		t.Errorf("expected output to contain 'SCAN COMPLETE', got:\n%s", output)
	}
}

func TestTerminalReporterRenderFailedScanner(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner: "broken-scanner",
			Status:  scanner.ScanFailed,
			Error:   "tool not found",
		},
	}

	var buf bytes.Buffer
	tr := reporter.NewTerminalReporter(&buf)
	tr.Render(results)

	output := buf.String()
	if !strings.Contains(output, "broken-scanner") {
		t.Errorf("expected output to contain failed scanner name 'broken-scanner', got:\n%s", output)
	}
}

func TestTerminalReporterSeveritySortOrder(t *testing.T) {
	// critical should appear before low in output
	lowFinding := makeFinding(scanner.SevLow, "Low Finding Title", "/low", "low detail", "low evidence", "low fix")
	criticalFinding := makeFinding(scanner.SevCritical, "Critical Finding Title", "/crit", "crit detail", "crit evidence", "crit fix")

	results := makeResults(lowFinding, criticalFinding)

	var buf bytes.Buffer
	tr := reporter.NewTerminalReporter(&buf)
	tr.Render(results)

	output := buf.String()
	critIdx := strings.Index(output, "Critical Finding Title")
	lowIdx := strings.Index(output, "Low Finding Title")

	if critIdx == -1 || lowIdx == -1 {
		t.Fatalf("expected both finding titles in output, got:\n%s", output)
	}
	if critIdx > lowIdx {
		t.Errorf("expected CRITICAL finding to appear before LOW finding in output")
	}
}

// --- CountBySeverity tests ---

func TestTerminalReporterSummary(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding(scanner.SevCritical, "C1", "", "", "", ""),
		makeFinding(scanner.SevCritical, "C2", "", "", "", ""),
		makeFinding(scanner.SevHigh, "H1", "", "", "", ""),
		makeFinding(scanner.SevMedium, "M1", "", "", "", ""),
		makeFinding(scanner.SevMedium, "M2", "", "", "", ""),
		makeFinding(scanner.SevMedium, "M3", "", "", "", ""),
		makeFinding(scanner.SevLow, "L1", "", "", "", ""),
	}

	counts := reporter.CountBySeverity(findings)

	if counts[scanner.SevCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[scanner.SevCritical])
	}
	if counts[scanner.SevHigh] != 1 {
		t.Errorf("expected 1 high, got %d", counts[scanner.SevHigh])
	}
	if counts[scanner.SevMedium] != 3 {
		t.Errorf("expected 3 medium, got %d", counts[scanner.SevMedium])
	}
	if counts[scanner.SevLow] != 1 {
		t.Errorf("expected 1 low, got %d", counts[scanner.SevLow])
	}
}

func TestCountBySeverityEmpty(t *testing.T) {
	counts := reporter.CountBySeverity([]scanner.Finding{})
	if len(counts) != 0 {
		t.Errorf("expected empty map for no findings, got %v", counts)
	}
}

// --- JSONReporter tests ---

func TestJSONReporterWrite(t *testing.T) {
	tmpDir := t.TempDir()

	criticalFinding := makeFinding(scanner.SevCritical, "Root SSH Enabled", "/etc/ssh/sshd_config", "PermitRootLogin yes", "PermitRootLogin yes", "Set PermitRootLogin no")
	highFinding := makeFinding(scanner.SevHigh, "World-Writable File", "/tmp/badfile", "chmod 777", "ls -la /tmp/badfile", "chmod 640 /tmp/badfile")
	mediumFinding := makeFinding(scanner.SevMedium, "Weak Cipher", "/etc/openssl.cnf", "RC4", "SSLCipher RC4", "Use AES-256")

	results := []scanner.ScanResult{
		{
			Scanner:  "ssh-scanner",
			Status:   scanner.ScanSuccess,
			Findings: []scanner.Finding{criticalFinding, highFinding},
		},
		{
			Scanner:  "tls-scanner",
			Status:   scanner.ScanSuccess,
			Findings: []scanner.Finding{mediumFinding},
		},
	}

	jr := reporter.NewJSONReporter(tmpDir)
	scanID, err := jr.Write(results, "testhost.local")
	if err != nil {
		t.Fatalf("unexpected error from Write: %v", err)
	}

	if scanID == "" {
		t.Fatal("expected non-empty scanID")
	}
	if !strings.HasPrefix(scanID, "dk-") {
		t.Errorf("expected scanID to start with 'dk-', got %q", scanID)
	}

	// Verify the output path
	expectedPath := jr.OutputPath(scanID)
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Fatalf("expected output file to exist at %s", expectedPath)
	}

	// Read and unmarshal
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var report reporter.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to unmarshal report JSON: %v", err)
	}

	// Verify host
	if report.Host != "testhost.local" {
		t.Errorf("expected host 'testhost.local', got %q", report.Host)
	}

	// Verify summary counts
	if report.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", report.Summary.Medium)
	}
	if report.Summary.Low != 0 {
		t.Errorf("expected 0 low, got %d", report.Summary.Low)
	}
	if report.Summary.Total != 3 {
		t.Errorf("expected 3 total, got %d", report.Summary.Total)
	}

	// Verify findings
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(report.Findings))
	}

	// Verify results
	if len(report.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Results))
	}

	// Verify scanID in report
	if report.ScanID != scanID {
		t.Errorf("expected scanID %q in report, got %q", scanID, report.ScanID)
	}

	// Verify directory structure: {outputDir}/{scanID}/findings.json
	expectedDir := filepath.Join(tmpDir, scanID)
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Errorf("expected directory %s to exist", expectedDir)
	}
}

func TestJSONReporterOutputPath(t *testing.T) {
	jr := reporter.NewJSONReporter("/some/output/dir")
	path := jr.OutputPath("dk-20240101-120000")
	expected := "/some/output/dir/dk-20240101-120000/findings.json"
	if path != expected {
		t.Errorf("expected path %q, got %q", expected, path)
	}
}

func TestTerminalReporter_LowSeverityColor(t *testing.T) {
	// A LOW severity finding exercises the default branch in severityColor.
	low := makeFinding(scanner.SevLow, "Low Title", "/low/path", "low detail", "low ev", "low fix")
	var buf bytes.Buffer
	tr := reporter.NewTerminalReporter(&buf)
	tr.Render(makeResults(low))
	output := buf.String()
	if !strings.Contains(output, "LOW") {
		t.Errorf("expected 'LOW' in output, got:\n%s", output)
	}
}

func TestSlackAlerter_MoreThan10Findings(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Build 15 findings so the "...and N more" branch fires.
	var findings []scanner.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, makeFinding(scanner.SevHigh, "Finding", "/path", "detail", "ev", "fix"))
	}
	a := reporter.NewSlackAlerter(srv.URL)
	report := reporter.AlertReport{
		Host:     "testhost",
		ScanID:   "dk-many",
		Time:     time.Now(),
		Findings: findings,
	}
	if err := a.Send(context.Background(), report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(received), "more findings") {
		t.Errorf("expected '...and N more findings' in payload, got: %s", string(received))
	}
}

func TestEmailAlerter_Name(t *testing.T) {
	a := reporter.NewEmailAlerter("to@example.com", "from@example.com", "smtp.example.com", "587")
	if a.Name() != "email" {
		t.Errorf("expected Name()='email', got %q", a.Name())
	}
}

func TestTerminalReporter_EmptyResults(t *testing.T) {
	// Rendering with no scan results (and therefore no findings) should still
	// produce a valid summary line and not panic.
	var buf bytes.Buffer
	tr := reporter.NewTerminalReporter(&buf)
	tr.Render([]scanner.ScanResult{})

	output := buf.String()
	if !strings.Contains(output, "SCAN COMPLETE") {
		t.Errorf("expected 'SCAN COMPLETE' in output for empty results, got:\n%s", output)
	}
	if !strings.Contains(output, "0 findings") {
		t.Errorf("expected '0 findings' in output for empty results, got:\n%s", output)
	}
}

func TestWebhookAlerter_NonSuccessResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	a := reporter.NewWebhookAlerter(srv.URL, "secret", false)
	report := reporter.AlertReport{Host: "testhost", ScanID: "dk-wh-err", Time: time.Now()}
	err := a.Send(context.Background(), report)
	if err == nil {
		t.Fatal("expected error for non-2xx webhook response, got nil")
	}
}

func TestJSONReporter_WriteToReadOnlyDir(t *testing.T) {
	// Use a path that cannot be created (file exists as a regular file, not dir).
	tmpDir := t.TempDir()
	// Create a file where we expect a directory — MkdirAll will fail.
	blocker := filepath.Join(tmpDir, "blocker")
	if err := os.WriteFile(blocker, []byte("block"), 0o444); err != nil {
		t.Fatalf("setup: could not create blocker file: %v", err)
	}

	// Try to write a report where outputDir = blocker (a file, not a dir).
	// The scanID subdirectory creation will fail.
	jr := reporter.NewJSONReporter(blocker)
	_, err := jr.Write([]scanner.ScanResult{}, "testhost")
	if err == nil {
		t.Fatal("expected error when outputDir is a file, not a directory")
	}
}

func TestCountBySeverity_EmptySlice(t *testing.T) {
	counts := reporter.CountBySeverity([]scanner.Finding{})
	if len(counts) != 0 {
		t.Errorf("expected empty map for empty slice, got %v", counts)
	}
	// Accessing a key that was never set should return the zero value (0).
	if counts[scanner.SevCritical] != 0 {
		t.Errorf("expected 0 critical for empty slice, got %d", counts[scanner.SevCritical])
	}
}

func TestJSONReporterWriteEmptyResults(t *testing.T) {
	tmpDir := t.TempDir()
	jr := reporter.NewJSONReporter(tmpDir)

	scanID, err := jr.Write([]scanner.ScanResult{}, "emptyhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(jr.OutputPath(scanID))
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var report reporter.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if report.Summary.Total != 0 {
		t.Errorf("expected 0 total findings, got %d", report.Summary.Total)
	}
	if report.Host != "emptyhost" {
		t.Errorf("expected host 'emptyhost', got %q", report.Host)
	}
}
