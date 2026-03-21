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
