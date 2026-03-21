package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/auth"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultOpts() scanner.ScanOptions {
	return scanner.ScanOptions{}
}

// writeTempSSHDConfig writes content to a temporary sshd_config file and
// returns the file path.
func writeTempSSHDConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp sshd_config: %v", err)
	}
	return path
}

// scanConfigFile is a test-helper that calls the unexported checkSshdConfig
// logic by invoking Scan against a patched SSHScanner whose config path is
// overridden via the exported testable entry-point.
//
// Because checkSshdConfig is unexported we exercise it indirectly through
// ScanConfig, a thin exported wrapper added for testing.
func scanConfigFile(t *testing.T, path string) []scanner.Finding {
	t.Helper()
	s := auth.NewSSHScannerWithConfig(path)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	return findings
}

// hasFindingTitle returns true if any finding title contains substr.
func hasFindingTitle(findings []scanner.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

// hasSeverity returns true if any finding has the given severity.
func hasSeverity(findings []scanner.Finding, sev scanner.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SSHScanner — interface tests
// ---------------------------------------------------------------------------

func TestSSHScanner_Interface(t *testing.T) {
	s := auth.NewSSHScanner()

	if got := s.Name(); got != "ssh" {
		t.Errorf("Name() = %q, want %q", got, "ssh")
	}
	if got := s.Category(); got != "auth" {
		t.Errorf("Category() = %q, want %q", got, "auth")
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

// ---------------------------------------------------------------------------
// SSHScanner — sshd_config detection tests
// ---------------------------------------------------------------------------

func TestSSHScanner_PermitRootLogin_Critical(t *testing.T) {
	cfg := "PermitRootLogin yes\n"
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if !hasFindingTitle(findings, "PermitRootLogin") {
		t.Errorf("expected finding about PermitRootLogin, got: %+v", findings)
	}
	if !hasSeverity(findings, scanner.SevCritical) {
		t.Error("expected CRITICAL severity for PermitRootLogin yes")
	}
}

func TestSSHScanner_PasswordAuthentication_High(t *testing.T) {
	cfg := "PasswordAuthentication yes\n"
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if !hasFindingTitle(findings, "PasswordAuthentication") {
		t.Errorf("expected finding about PasswordAuthentication, got: %+v", findings)
	}
	if !hasSeverity(findings, scanner.SevHigh) {
		t.Error("expected HIGH severity for PasswordAuthentication yes")
	}
}

func TestSSHScanner_MaxAuthTries_Medium(t *testing.T) {
	cfg := "MaxAuthTries 10\n"
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if !hasFindingTitle(findings, "MaxAuthTries") {
		t.Errorf("expected finding about MaxAuthTries, got: %+v", findings)
	}
	if !hasSeverity(findings, scanner.SevMedium) {
		t.Error("expected MEDIUM severity for MaxAuthTries > 6")
	}
}

func TestSSHScanner_MaxAuthTries_NotFlagged_When6OrLess(t *testing.T) {
	for _, val := range []string{"3", "6"} {
		cfg := "MaxAuthTries " + val + "\n"
		path := writeTempSSHDConfig(t, cfg)
		findings := scanConfigFile(t, path)
		for _, f := range findings {
			if strings.Contains(f.Title, "MaxAuthTries") {
				t.Errorf("MaxAuthTries %s should not be flagged, got finding: %+v", val, f)
			}
		}
	}
}

func TestSSHScanner_PermitEmptyPasswords_Critical(t *testing.T) {
	cfg := "PermitEmptyPasswords yes\n"
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if !hasFindingTitle(findings, "PermitEmptyPasswords") {
		t.Errorf("expected finding about PermitEmptyPasswords, got: %+v", findings)
	}
	if !hasSeverity(findings, scanner.SevCritical) {
		t.Error("expected CRITICAL severity for PermitEmptyPasswords yes")
	}
}

func TestSSHScanner_MultipleWeakSettings(t *testing.T) {
	cfg := `# sshd_config
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 12
PermitEmptyPasswords yes
`
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if len(findings) < 4 {
		t.Errorf("expected at least 4 findings for weak config, got %d: %+v", len(findings), findings)
	}
}

func TestSSHScanner_CleanConfig_NoFindings(t *testing.T) {
	cfg := `# Hardened sshd_config
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
PermitEmptyPasswords no
`
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for hardened config, got %d: %+v", len(findings), findings)
	}
}

func TestSSHScanner_FindingsHaveRequiredFields(t *testing.T) {
	cfg := "PermitRootLogin yes\nPasswordAuthentication yes\n"
	path := writeTempSSHDConfig(t, cfg)
	findings := scanConfigFile(t, path)

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
		if f.Location == "" {
			t.Errorf("finding has empty Location: %+v", f)
		}
		if f.Evidence == "" {
			t.Errorf("finding has empty Evidence: %+v", f)
		}
	}
}

func TestSSHScanner_AuthorizedKeys_WorldReadable(t *testing.T) {
	// Create a fake home directory tree with a world-readable authorized_keys.
	homeDir := t.TempDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	keyFile := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyFile, []byte("ssh-ed25519 AAAA...\n"), 0o644); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	s := auth.NewSSHScannerWithHomesDir(writeTempSSHDConfig(t, ""), homeDir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundWorldReadable := false
	for _, f := range findings {
		if strings.Contains(f.Title, "world-readable") {
			foundWorldReadable = true
			if f.Severity != scanner.SevHigh {
				t.Errorf("world-readable finding severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !foundWorldReadable {
		t.Errorf("expected world-readable finding, got: %+v", findings)
	}
}

func TestSSHScanner_AuthorizedKeys_CountReported(t *testing.T) {
	homeDir := t.TempDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	keyFile := filepath.Join(sshDir, "authorized_keys")
	content := "ssh-ed25519 AAAA...\nssh-rsa BBBB...\n"
	if err := os.WriteFile(keyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	s := auth.NewSSHScannerWithHomesDir(writeTempSSHDConfig(t, ""), homeDir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundCount := false
	for _, f := range findings {
		if strings.Contains(f.Title, "authorized_keys file present") {
			foundCount = true
			if f.Metadata["key_count"] != "2" {
				t.Errorf("key_count metadata = %q, want %q", f.Metadata["key_count"], "2")
			}
		}
	}
	if !foundCount {
		t.Errorf("expected authorized_keys presence finding, got: %+v", findings)
	}
}

// verifyInterfaceCompliance is a compile-time check that all auth scanners
// satisfy the scanner.Scanner interface.
func verifyInterfaceCompliance() {
	var _ scanner.Scanner = (*auth.SSHScanner)(nil)
	var _ scanner.Scanner = (*auth.UsersScanner)(nil)
	var _ scanner.Scanner = (*auth.BrowserScanner)(nil)
}

// ---------------------------------------------------------------------------
// UsersScanner — interface tests
// ---------------------------------------------------------------------------

func TestUsersScanner_Interface(t *testing.T) {
	s := auth.NewUsersScanner()

	if got := s.Name(); got != "users" {
		t.Errorf("Name() = %q, want %q", got, "users")
	}
	if got := s.Category(); got != "auth" {
		t.Errorf("Category() = %q, want %q", got, "auth")
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

func TestUsersScanner_StubReturnsNoFindings(t *testing.T) {
	s := auth.NewUsersScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("stub Scan should return 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// BrowserScanner — interface tests
// ---------------------------------------------------------------------------

func TestBrowserScanner_Interface(t *testing.T) {
	s := auth.NewBrowserScanner()

	if got := s.Name(); got != "browser" {
		t.Errorf("Name() = %q, want %q", got, "browser")
	}
	if got := s.Category(); got != "auth" {
		t.Errorf("Category() = %q, want %q", got, "auth")
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

func TestBrowserScanner_StubReturnsNoFindings(t *testing.T) {
	s := auth.NewBrowserScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("stub Scan should return 0 findings, got %d", len(findings))
	}
}

