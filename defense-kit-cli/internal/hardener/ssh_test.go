package hardener_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/hardener"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// TestSSHHardener_Name
// ---------------------------------------------------------------------------

func TestSSHHardener_Name(t *testing.T) {
	h := hardener.NewSSHHardener()
	if h.Name() != "ssh" {
		t.Errorf("Name() = %q, want %q", h.Name(), "ssh")
	}
}

// ---------------------------------------------------------------------------
// TestSSHHardener_CanFix
// ---------------------------------------------------------------------------

func TestSSHHardener_CanFix(t *testing.T) {
	h := hardener.NewSSHHardener()

	cases := []struct {
		name    string
		finding scanner.Finding
		want    bool
	}{
		{
			name:    "ssh PermitRootLogin",
			finding: scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"},
			want:    true,
		},
		{
			name:    "ssh root login enabled",
			finding: scanner.Finding{Scanner: "ssh", Title: "Root login enabled"},
			want:    true,
		},
		{
			name:    "ssh PasswordAuthentication",
			finding: scanner.Finding{Scanner: "ssh", Title: "PasswordAuthentication"},
			want:    true,
		},
		{
			name:    "ssh password authentication enabled",
			finding: scanner.Finding{Scanner: "ssh", Title: "Password authentication enabled"},
			want:    true,
		},
		{
			name:    "ssh PermitEmptyPasswords",
			finding: scanner.Finding{Scanner: "ssh", Title: "PermitEmptyPasswords"},
			want:    true,
		},
		{
			name:    "ssh MaxAuthTries",
			finding: scanner.Finding{Scanner: "ssh", Title: "MaxAuthTries"},
			want:    true,
		},
		{
			name:    "non-ssh scanner",
			finding: scanner.Finding{Scanner: "network", Title: "PermitRootLogin"},
			want:    false,
		},
		{
			name:    "ssh scanner unknown title",
			finding: scanner.Finding{Scanner: "ssh", Title: "SomeOtherIssue"},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.CanFix(tc.finding)
			if got != tc.want {
				t.Errorf("CanFix(%q) = %v, want %v", tc.finding.Title, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSSHHardener_Preview
// ---------------------------------------------------------------------------

func TestSSHHardener_Preview(t *testing.T) {
	configPath := writeTempConfig(t, "PermitRootLogin yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{
		ID:      "ssh-001",
		Scanner: "ssh",
		Title:   "PermitRootLogin",
	}

	plan := h.Preview(f)

	if plan.Finding.ID != f.ID {
		t.Errorf("plan.Finding.ID = %q, want %q", plan.Finding.ID, f.ID)
	}
	if plan.Description == "" {
		t.Error("plan.Description is empty")
	}
	if len(plan.Actions) == 0 {
		t.Fatal("plan.Actions is empty")
	}
	if plan.Actions[0].Type != hardener.FileEdit {
		t.Errorf("plan.Actions[0].Type = %v, want FileEdit", plan.Actions[0].Type)
	}
	if plan.Actions[0].Target != configPath {
		t.Errorf("plan.Actions[0].Target = %q, want %q", plan.Actions[0].Target, configPath)
	}
	if len(plan.Actions[0].Args) < 2 {
		t.Fatal("plan.Actions[0].Args has fewer than 2 elements")
	}
	if !strings.EqualFold(plan.Actions[0].Args[0], "PermitRootLogin") {
		t.Errorf("args[0] = %q, want PermitRootLogin", plan.Actions[0].Args[0])
	}
	if plan.Actions[0].Args[1] != "no" {
		t.Errorf("args[1] = %q, want %q", plan.Actions[0].Args[1], "no")
	}
	if len(plan.Rollback.Steps) == 0 {
		t.Error("plan.Rollback.Steps is empty")
	}
}

// ---------------------------------------------------------------------------
// TestSSHHardener_ApplyAndVerify
// ---------------------------------------------------------------------------

func TestSSHHardener_ApplyAndVerify(t *testing.T) {
	configPath := writeTempConfig(t, "PermitRootLogin yes\nPasswordAuthentication yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	// The file should now contain "PermitRootLogin no".
	data, _ := os.ReadFile(configPath)
	content := string(data)
	if !strings.Contains(content, "PermitRootLogin no") {
		t.Errorf("config after apply does not contain 'PermitRootLogin no'; got:\n%s", content)
	}

	if err := h.Verify(context.Background(), plan); err != nil {
		t.Errorf("Verify error after Apply: %v", err)
	}
}

func TestSSHHardener_ApplyAndVerify_CommentedDirective(t *testing.T) {
	configPath := writeTempConfig(t, "#PermitRootLogin yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	if err := h.Verify(context.Background(), plan); err != nil {
		t.Errorf("Verify error after Apply on commented directive: %v", err)
	}
}

func TestSSHHardener_ApplyAndVerify_MissingDirective(t *testing.T) {
	// Directive absent — Apply should append it.
	configPath := writeTempConfig(t, "# default sshd config\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "MaxAuthTries"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	if err := h.Verify(context.Background(), plan); err != nil {
		t.Errorf("Verify error after Apply (directive was absent): %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestSSHHardener_Rollback
// ---------------------------------------------------------------------------

func TestSSHHardener_Rollback(t *testing.T) {
	originalContent := "PermitRootLogin yes\n"
	configPath := writeTempConfig(t, originalContent)
	backupDir := t.TempDir()

	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)

	// Create a backup so Rollback can restore.
	backupPath, err := hardener.BackupFile(configPath, backupDir)
	if err != nil {
		t.Fatalf("BackupFile: %v", err)
	}
	if plan.BackupPaths == nil {
		plan.BackupPaths = make(map[string]string)
	}
	plan.BackupPaths[configPath] = backupPath

	// Apply the fix.
	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	// Confirm the file was actually changed.
	after, _ := os.ReadFile(configPath)
	if strings.Contains(string(after), "yes") {
		t.Fatalf("expected Apply to change 'yes' to 'no'; file still contains 'yes'")
	}

	// Rollback.
	if err := h.Rollback(context.Background(), plan); err != nil {
		t.Fatalf("Rollback error: %v", err)
	}

	// Confirm the file was restored.
	restored, _ := os.ReadFile(configPath)
	if string(restored) != originalContent {
		t.Errorf("after Rollback file = %q, want %q", string(restored), originalContent)
	}
}

// ---------------------------------------------------------------------------
// All directive types
// ---------------------------------------------------------------------------

func TestSSHHardener_AllDirectiveTypes(t *testing.T) {
	directives := []struct {
		title    string
		wantKey  string
		wantVal  string
	}{
		{"PermitRootLogin", "PermitRootLogin", "no"},
		{"Root login enabled", "PermitRootLogin", "no"},
		{"PasswordAuthentication", "PasswordAuthentication", "no"},
		{"Password authentication enabled", "PasswordAuthentication", "no"},
		{"PermitEmptyPasswords", "PermitEmptyPasswords", "no"},
		{"MaxAuthTries", "MaxAuthTries", "3"},
	}

	for _, d := range directives {
		t.Run(d.title, func(t *testing.T) {
			// Config has the directive set to a different value.
			initialContent := d.wantKey + " yes\n"
			configPath := writeTempConfig(t, initialContent)
			h := hardener.NewSSHHardenerWithConfig(configPath)

			f := scanner.Finding{Scanner: "ssh", Title: d.title}
			if !h.CanFix(f) {
				t.Fatalf("CanFix returned false for title %q", d.title)
			}

			plan := h.Preview(f)
			if len(plan.Actions) == 0 {
				t.Fatal("Preview returned no actions")
			}
			if plan.Actions[0].Args[0] != d.wantKey {
				t.Errorf("directive: got %q, want %q", plan.Actions[0].Args[0], d.wantKey)
			}
			if plan.Actions[0].Args[1] != d.wantVal {
				t.Errorf("value: got %q, want %q", plan.Actions[0].Args[1], d.wantVal)
			}

			if err := h.Apply(context.Background(), plan); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if err := h.Verify(context.Background(), plan); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestSSHHardener_AbsentDirective_GetsAdded(t *testing.T) {
	// Config has no MaxAuthTries directive at all.
	configPath := writeTempConfig(t, "# empty sshd_config\nPort 22\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "MaxAuthTries"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Directive should now be present.
	data, _ := os.ReadFile(configPath)
	if !strings.Contains(string(data), "MaxAuthTries 3") {
		t.Errorf("expected MaxAuthTries 3 to be appended; got:\n%s", string(data))
	}

	if err := h.Verify(context.Background(), plan); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSSHHardener_PermitEmptyPasswords_Apply(t *testing.T) {
	configPath := writeTempConfig(t, "PermitEmptyPasswords yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitEmptyPasswords"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	data, _ := os.ReadFile(configPath)
	if !strings.Contains(string(data), "PermitEmptyPasswords no") {
		t.Errorf("PermitEmptyPasswords not set to no; got:\n%s", string(data))
	}
}

func TestSSHHardener_PasswordAuth_Apply(t *testing.T) {
	configPath := writeTempConfig(t, "PasswordAuthentication yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PasswordAuthentication"}
	plan := h.Preview(f)

	if err := h.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := h.Verify(context.Background(), plan); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSSHHardener_Rollback_NoBackup(t *testing.T) {
	configPath := writeTempConfig(t, "PermitRootLogin yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)
	// Do NOT set a backup path.

	err := h.Rollback(context.Background(), plan)
	if err == nil {
		t.Error("expected error when rolling back without a backup path")
	}
}

// TestSSHHardener_Apply_NoActions exercises the "no actions" early return in Apply.
func TestSSHHardener_Apply_NoActions(t *testing.T) {
	h := hardener.NewSSHHardener()

	plan := hardener.FixPlan{} // no actions

	err := h.Apply(context.Background(), plan)
	if err == nil {
		t.Error("Apply with no actions should return error")
	}
}

// TestSSHHardener_Verify_NoActions exercises the "no actions" early return in Verify.
func TestSSHHardener_Verify_NoActions(t *testing.T) {
	h := hardener.NewSSHHardener()

	plan := hardener.FixPlan{} // no actions

	err := h.Verify(context.Background(), plan)
	if err == nil {
		t.Error("Verify with no actions should return error")
	}
}

// TestSSHHardener_Verify_WrongValue verifies that Verify returns an error when
// the directive is present but has an unexpected value.
func TestSSHHardener_Verify_WrongValue(t *testing.T) {
	configPath := writeTempConfig(t, "PermitRootLogin yes\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)
	// Don't call Apply; file still has "yes" not "no".

	err := h.Verify(context.Background(), plan)
	if err == nil {
		t.Error("Verify should fail when directive has wrong value")
	}
}

// TestSSHHardener_Verify_DirectiveNotFound verifies Verify fails when directive is absent.
func TestSSHHardener_Verify_DirectiveNotFound(t *testing.T) {
	configPath := writeTempConfig(t, "# no directives here\nPort 22\n")
	h := hardener.NewSSHHardenerWithConfig(configPath)

	f := scanner.Finding{Scanner: "ssh", Title: "PermitRootLogin"}
	plan := h.Preview(f)

	err := h.Verify(context.Background(), plan)
	if err == nil {
		t.Error("Verify should fail when directive is absent from config")
	}
}

// TestSSHHardener_Apply_MissingArgs exercises the "action missing args" path.
func TestSSHHardener_Apply_MissingArgs(t *testing.T) {
	h := hardener.NewSSHHardener()

	plan := hardener.FixPlan{
		Actions: []hardener.FixAction{
			{Type: hardener.FileEdit, Target: "/etc/ssh/sshd_config"},
			// No Args — should trigger error.
		},
	}

	err := h.Apply(context.Background(), plan)
	if err == nil {
		t.Error("Apply with missing args should return error")
	}
}

// TestBackupFile_ErrorOnNonExistentSource verifies BackupFile returns error for missing source.
func TestBackupFile_ErrorOnNonExistentSource(t *testing.T) {
	backupDir := t.TempDir()
	_, err := hardener.BackupFile("/nonexistent/file/xyz.conf", backupDir)
	if err == nil {
		t.Error("BackupFile should return error for non-existent source")
	}
}

// TestRestoreFile_ErrorOnNonExistentBackup verifies RestoreFile returns error for missing backup.
func TestRestoreFile_ErrorOnNonExistentBackup(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.conf")
	err := hardener.RestoreFile("/nonexistent/backup.conf", target)
	if err == nil {
		t.Error("RestoreFile should return error for non-existent backup")
	}
}
