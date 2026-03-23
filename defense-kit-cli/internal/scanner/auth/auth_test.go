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

// ---------------------------------------------------------------------------
// UsersScanner — helpers
// ---------------------------------------------------------------------------

// writeTempFile writes content to a named file inside a temp dir and returns
// the absolute path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

// newUsersScanner builds a UsersScanner pointing at the given temp files.
// Any path that is empty string is replaced with a nonexistent file so the
// scanner can handle missing optional data gracefully.
func newUsersScanner(t *testing.T, passwd, shadow, sudoers, sudoersD, group string) *auth.UsersScanner {
	t.Helper()
	nonexistent := filepath.Join(t.TempDir(), "nonexistent")
	if passwd == "" {
		passwd = nonexistent
	}
	if shadow == "" {
		shadow = nonexistent
	}
	if sudoers == "" {
		sudoers = nonexistent
	}
	if group == "" {
		group = nonexistent
	}
	return auth.NewUsersScannerWithPaths(passwd, shadow, sudoers, sudoersD, group)
}

// ---------------------------------------------------------------------------
// UsersScanner — UID 0 detection
// ---------------------------------------------------------------------------

func TestUsersScanner_UID0Backdoor_Critical(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"backdoor:x:0:0:evil:/home/backdoor:/bin/bash\n"+
			"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")

	s := newUsersScanner(t, passwd, "", "", "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "backdoor") {
			found = true
			if f.Severity != scanner.SevCritical {
				t.Errorf("UID 0 finding severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for backdoor UID 0 account, got: %+v", findings)
	}
}

func TestUsersScanner_RootUID0_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd",
		"root:x:0:0:root:/root:/bin/bash\n")

	s := newUsersScanner(t, passwd, "", "", "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "Non-root account with UID 0") {
			t.Errorf("root account should not be flagged for UID 0, got: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// UsersScanner — passwordless accounts
// ---------------------------------------------------------------------------

func TestUsersScanner_PasswordlessWithShell_High(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"ghost:x:1001:1001:Ghost User:/home/ghost:/bin/bash\n")
	shadow := writeTempFile(t, dir, "shadow",
		"root:$6$hash:19000:0:99999:7:::\n"+
			"ghost::19000:0:99999:7:::\n") // empty password field

	s := newUsersScanner(t, passwd, shadow, "", "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "ghost") && strings.Contains(f.Title, "no password") {
			found = true
			if f.Severity != scanner.SevHigh {
				t.Errorf("passwordless finding severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for passwordless account 'ghost', got: %+v", findings)
	}
}

func TestUsersScanner_PasswordlessNologin_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd",
		"daemon:x:2:2:Daemon:/sbin:/usr/sbin/nologin\n")
	shadow := writeTempFile(t, dir, "shadow",
		"daemon::19000:0:99999:7:::\n") // empty password but nologin shell

	s := newUsersScanner(t, passwd, shadow, "", "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "daemon") && strings.Contains(f.Title, "no password") {
			t.Errorf("nologin account should not be flagged for no password, got: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// UsersScanner — NOPASSWD sudoers detection
// ---------------------------------------------------------------------------

func TestUsersScanner_SudoersNOPASSWD_High(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd", "root:x:0:0:root:/root:/bin/bash\n")
	sudoers := writeTempFile(t, dir, "sudoers",
		"# /etc/sudoers\n"+
			"root    ALL=(ALL:ALL) ALL\n"+
			"deploy  ALL=(ALL) NOPASSWD: ALL\n")

	s := newUsersScanner(t, passwd, "", sudoers, "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "NOPASSWD") && strings.Contains(f.Title, "deploy") {
			found = true
			if f.Severity != scanner.SevHigh {
				t.Errorf("NOPASSWD finding severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for NOPASSWD deploy, got: %+v", findings)
	}
}

func TestUsersScanner_SudoersNOPASSWD_InSubdir(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd", "root:x:0:0:root:/root:/bin/bash\n")
	// No main sudoers file, but a drop-in file in sudoers.d
	sudoersDDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(sudoersDDir, 0o755); err != nil {
		t.Fatalf("mkdir sudoers.d: %v", err)
	}
	writeTempFile(t, sudoersDDir, "ci-runner",
		"ci ALL=(ALL) NOPASSWD: /usr/bin/docker\n")

	nonexistent := filepath.Join(dir, "nonexistent")
	s := auth.NewUsersScannerWithPaths(passwd, nonexistent, nonexistent, sudoersDDir, nonexistent)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "NOPASSWD") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NOPASSWD finding from sudoers.d drop-in, got: %+v", findings)
	}
}

func TestUsersScanner_SudoersClean_NoFindings(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd", "root:x:0:0:root:/root:/bin/bash\n")
	sudoers := writeTempFile(t, dir, "sudoers",
		"root    ALL=(ALL:ALL) ALL\n"+
			"%sudo   ALL=(ALL:ALL) ALL\n")

	s := newUsersScanner(t, passwd, "", sudoers, "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "NOPASSWD") {
			t.Errorf("clean sudoers should not produce NOPASSWD findings, got: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// UsersScanner — privileged group membership
// ---------------------------------------------------------------------------

func TestUsersScanner_PrivilegedGroups_Low(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd", "root:x:0:0:root:/root:/bin/bash\n")
	group := writeTempFile(t, dir, "group",
		"sudo:x:27:alice,bob\n"+
			"wheel:x:10:charlie\n"+
			"nogroup:x:65534:\n")

	s := newUsersScanner(t, passwd, "", "", "", group)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	foundSudo := false
	foundWheel := false
	for _, f := range findings {
		if strings.Contains(f.Title, `"sudo"`) {
			foundSudo = true
			if f.Severity != scanner.SevLow {
				t.Errorf("sudo group finding severity = %s, want LOW", f.Severity)
			}
		}
		if strings.Contains(f.Title, `"wheel"`) {
			foundWheel = true
		}
	}
	if !foundSudo {
		t.Errorf("expected LOW finding for sudo group membership, got: %+v", findings)
	}
	if !foundWheel {
		t.Errorf("expected LOW finding for wheel group membership, got: %+v", findings)
	}
}

func TestUsersScanner_PrivilegedGroups_EmptyMembers_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd", "root:x:0:0:root:/root:/bin/bash\n")
	group := writeTempFile(t, dir, "group",
		"sudo:x:27:\n") // group exists but has no members

	s := newUsersScanner(t, passwd, "", "", "", group)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, `"sudo"`) {
			t.Errorf("empty sudo group should not produce a finding, got: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// UsersScanner — findings quality
// ---------------------------------------------------------------------------

func TestUsersScanner_FindingsHaveRequiredFields(t *testing.T) {
	dir := t.TempDir()
	passwd := writeTempFile(t, dir, "passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"evil:x:0:0:evil:/home/evil:/bin/bash\n")
	sudoers := writeTempFile(t, dir, "sudoers",
		"attacker  ALL=(ALL) NOPASSWD: ALL\n")

	s := newUsersScanner(t, passwd, "", sudoers, "", "")
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

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

