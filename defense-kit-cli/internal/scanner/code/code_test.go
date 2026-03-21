package code_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/code"
)

// ---------------------------------------------------------------------------
// Interface tests for all four scanners
// ---------------------------------------------------------------------------

func TestCredentialsScanner_Interface(t *testing.T) {
	s := code.NewCredentialsScanner()

	if s.Name() != "credentials" {
		t.Errorf("Name() = %q, want %q", s.Name(), "credentials")
	}
	if s.Category() != "code" {
		t.Errorf("Category() = %q, want %q", s.Category(), "code")
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

	// Verify it satisfies the scanner.Scanner interface at compile time.
	var _ scanner.Scanner = s
}

func TestSupplyChainScanner_Interface(t *testing.T) {
	s := code.NewSupplyChainScanner()

	if s.Name() != "supply_chain" {
		t.Errorf("Name() = %q, want %q", s.Name(), "supply_chain")
	}
	if s.Category() != "code" {
		t.Errorf("Category() = %q, want %q", s.Category(), "code")
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

	var _ scanner.Scanner = s
}

func TestContainersScanner_Interface(t *testing.T) {
	s := code.NewContainersScanner()

	if s.Name() != "containers" {
		t.Errorf("Name() = %q, want %q", s.Name(), "containers")
	}
	if s.Category() != "code" {
		t.Errorf("Category() = %q, want %q", s.Category(), "code")
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

	var _ scanner.Scanner = s
}

func TestGitHooksScanner_Interface(t *testing.T) {
	s := code.NewGitHooksScanner()

	if s.Name() != "git_hooks" {
		t.Errorf("Name() = %q, want %q", s.Name(), "git_hooks")
	}
	if s.Category() != "code" {
		t.Errorf("Category() = %q, want %q", s.Category(), "code")
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

	var _ scanner.Scanner = s
}

// ---------------------------------------------------------------------------
// Stub scanners return no findings and no error
// ---------------------------------------------------------------------------

func TestSupplyChainScanner_Stub(t *testing.T) {
	s := code.NewSupplyChainScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from stub, got %d", len(findings))
	}
}

func TestContainersScanner_Stub(t *testing.T) {
	s := code.NewContainersScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from stub, got %d", len(findings))
	}
}

func TestGitHooksScanner_Stub(t *testing.T) {
	s := code.NewGitHooksScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from stub, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// CredentialsScanner detection tests
// ---------------------------------------------------------------------------

// TestCredentialsScanner_DetectsAWSAccessKey verifies that a fake AWS access key
// (AKIA…) in a file is reported as a CRITICAL finding.
func TestCredentialsScanner_DetectsAWSAccessKey(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp .env: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := findingsByTitle(findings, "AWS access key exposed")
	if len(found) == 0 {
		t.Fatal("expected at least one finding for AWS access key, got none")
	}
	for _, f := range found {
		assertFindingFields(t, f)
		if f.Severity != scanner.SevCritical {
			t.Errorf("severity = %v, want CRITICAL", f.Severity)
		}
	}
}

// TestCredentialsScanner_DetectsAWSSecretKey verifies detection of an AWS secret
// access key assignment.
func TestCredentialsScanner_DetectsAWSSecretKey(t *testing.T) {
	dir := t.TempDir()
	credsFile := filepath.Join(dir, "credentials")

	content := "[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(credsFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp credentials file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := findingsByTitle(findings, "AWS secret access key exposed")
	if len(found) == 0 {
		t.Fatal("expected at least one finding for AWS secret key, got none")
	}
	for _, f := range found {
		assertFindingFields(t, f)
		if f.Severity != scanner.SevCritical {
			t.Errorf("severity = %v, want CRITICAL", f.Severity)
		}
	}
}

// TestCredentialsScanner_DetectsPrivateKey verifies that a PEM private key header
// in a file produces a CRITICAL finding.
func TestCredentialsScanner_DetectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id_rsa")

	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(keyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp key file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := findingsByTitle(findings, "Private key material exposed")
	if len(found) == 0 {
		t.Fatal("expected at least one finding for private key, got none")
	}
	for _, f := range found {
		assertFindingFields(t, f)
		if f.Severity != scanner.SevCritical {
			t.Errorf("severity = %v, want CRITICAL", f.Severity)
		}
	}
}

// TestCredentialsScanner_DetectsAPIKey verifies detection of a generic API key.
func TestCredentialsScanner_DetectsAPIKey(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	content := "api_key: abcdef1234567890abcdef1234567890\n"
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := findingsByTitle(findings, "Generic API key or token exposed")
	if len(found) == 0 {
		t.Fatal("expected at least one finding for API key, got none")
	}
	for _, f := range found {
		assertFindingFields(t, f)
		if f.Severity != scanner.SevHigh {
			t.Errorf("severity = %v, want HIGH", f.Severity)
		}
	}
}

// TestCredentialsScanner_DetectsPassword verifies detection of a hardcoded password.
func TestCredentialsScanner_DetectsPassword(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "app.conf")

	content := "database_password=supersecretpassword123\n"
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := findingsByTitle(findings, "Hardcoded password detected")
	if len(found) == 0 {
		t.Fatal("expected at least one finding for hardcoded password, got none")
	}
	for _, f := range found {
		assertFindingFields(t, f)
		if f.Severity != scanner.SevMedium {
			t.Errorf("severity = %v, want MEDIUM", f.Severity)
		}
	}
}

// TestCredentialsScanner_CleanFileProducesNoFindings verifies that a file with
// no credentials produces zero findings.
func TestCredentialsScanner_CleanFileProducesNoFindings(t *testing.T) {
	dir := t.TempDir()
	cleanFile := filepath.Join(dir, "readme.txt")

	content := "This is a clean file.\nNo secrets here.\nJust ordinary text.\n"
	if err := os.WriteFile(cleanFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write clean file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d: %+v", len(findings), findings)
	}
}

// TestCredentialsScanner_FindingFields verifies that every finding from a
// secrets-laden file has all required fields populated.
func TestCredentialsScanner_FindingFields(t *testing.T) {
	dir := t.TempDir()
	secretsFile := filepath.Join(dir, "secrets.env")

	content := strings.Join([]string{
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"-----BEGIN RSA PRIVATE KEY-----",
	}, "\n") + "\n"

	if err := os.WriteFile(secretsFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write secrets file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings but got none")
	}

	for _, f := range findings {
		assertFindingFields(t, f)
	}
}

// TestCredentialsScanner_SkipsBinaryFiles verifies that binary files (containing
// null bytes) are not scanned.
func TestCredentialsScanner_SkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	binaryFile := filepath.Join(dir, "binary.bin")

	// Create a file whose first 512 bytes include a null byte — looks like a binary.
	content := make([]byte, 600)
	copy(content, []byte("AKIAIOSFODNN7EXAMPLE"))
	content[100] = 0x00 // inject null byte to mark as binary

	if err := os.WriteFile(binaryFile, content, 0o644); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for binary file, got %d", len(findings))
	}
}

// TestCredentialsScanner_EvidenceTruncated verifies that very long lines are
// truncated to 200 characters in the Evidence field.
func TestCredentialsScanner_EvidenceTruncated(t *testing.T) {
	dir := t.TempDir()
	longFile := filepath.Join(dir, "long.env")

	// Build a line that is well over 200 chars and contains a pattern.
	padding := strings.Repeat("X", 300)
	content := "AKIAIOSFODNN7EXAMPLE" + padding + "\n"
	if err := os.WriteFile(longFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write long file: %v", err)
	}

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if len(f.Evidence) > 200 {
			t.Errorf("Evidence length %d exceeds 200 chars", len(f.Evidence))
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func findingsByTitle(findings []scanner.Finding, title string) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if f.Title == title {
			out = append(out, f)
		}
	}
	return out
}

func assertFindingFields(t *testing.T, f scanner.Finding) {
	t.Helper()
	if f.ID == "" {
		t.Error("finding has empty ID")
	}
	if f.Scanner == "" {
		t.Error("finding has empty Scanner")
	}
	if f.Title == "" {
		t.Error("finding has empty Title")
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
