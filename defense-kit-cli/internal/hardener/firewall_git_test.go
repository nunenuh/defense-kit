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
// FirewallHardener tests
// ---------------------------------------------------------------------------

func TestFirewallHardener_CanFix(t *testing.T) {
	h := hardener.NewFirewallHardenerForTest()

	cases := []struct {
		name    string
		finding scanner.Finding
		want    bool
	}{
		{
			name:    "firewall scanner - missing firewall",
			finding: scanner.Finding{Scanner: "firewall", Title: "Missing firewall"},
			want:    true,
		},
		{
			name:    "firewall scanner - no firewall",
			finding: scanner.Finding{Scanner: "firewall", Title: "No firewall detected"},
			want:    true,
		},
		{
			name:    "firewall scanner - firewall disabled",
			finding: scanner.Finding{Scanner: "firewall", Title: "Firewall disabled"},
			want:    true,
		},
		{
			name:    "firewall scanner - firewall not enabled",
			finding: scanner.Finding{Scanner: "firewall", Title: "Firewall not enabled"},
			want:    true,
		},
		{
			name:    "firewall scanner - ip_forward enabled",
			finding: scanner.Finding{Scanner: "firewall", Title: "ip_forward enabled"},
			want:    true,
		},
		{
			name:    "firewall scanner - ip forward enabled",
			finding: scanner.Finding{Scanner: "firewall", Title: "IP forward enabled"},
			want:    true,
		},
		{
			name:    "firewall scanner - ip forwarding enabled",
			finding: scanner.Finding{Scanner: "firewall", Title: "IP forwarding enabled"},
			want:    true,
		},
		{
			name:    "wrong scanner - firewall finding",
			finding: scanner.Finding{Scanner: "ssh", Title: "Missing firewall"},
			want:    false,
		},
		{
			name:    "wrong scanner - network finding",
			finding: scanner.Finding{Scanner: "network", Title: "Missing firewall"},
			want:    false,
		},
		{
			name:    "firewall scanner - unrelated title",
			finding: scanner.Finding{Scanner: "firewall", Title: "Open port 8080"},
			want:    false,
		},
		{
			name:    "git_hooks scanner - unrelated title",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Malicious git hook"},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.CanFix(tc.finding)
			if got != tc.want {
				t.Errorf("CanFix(%q/%q) = %v, want %v", tc.finding.Scanner, tc.finding.Title, got, tc.want)
			}
		})
	}
}

func TestFirewallHardener_Preview(t *testing.T) {
	h := hardener.NewFirewallHardenerForTest()

	f := scanner.Finding{
		ID:      "fw-001",
		Scanner: "firewall",
		Title:   "Missing firewall",
	}

	plan := h.Preview(f)

	if plan.Finding.ID != f.ID {
		t.Errorf("plan.Finding.ID = %q, want %q", plan.Finding.ID, f.ID)
	}

	if plan.Description == "" {
		t.Error("plan.Description is empty")
	}

	// Verify plan includes SSH allow to prevent lockout.
	sshFound := false
	for _, action := range plan.Actions {
		for _, arg := range action.Args {
			if strings.Contains(arg, "22") || strings.EqualFold(arg, "SSH") {
				sshFound = true
				break
			}
		}
	}
	if !sshFound {
		t.Error("plan.Actions does not include an SSH (port 22) allow rule — lockout risk!")
	}

	// Verify the enable command is present.
	enableFound := false
	for _, action := range plan.Actions {
		for _, arg := range action.Args {
			if arg == "enable" {
				enableFound = true
				break
			}
		}
	}
	if !enableFound {
		t.Error("plan.Actions does not include ufw enable command")
	}

	// Verify rollback is present.
	if len(plan.Rollback.Steps) == 0 {
		t.Error("plan.Rollback.Steps is empty")
	}

	// Verify there are at least 4 actions (deny incoming, allow outgoing, allow SSH, enable).
	if len(plan.Actions) < 4 {
		t.Errorf("plan.Actions has %d elements, want at least 4", len(plan.Actions))
	}
}

func TestFirewallHardener_Name(t *testing.T) {
	h := hardener.NewFirewallHardenerForTest()
	if h.Name() != "firewall" {
		t.Errorf("Name() = %q, want %q", h.Name(), "firewall")
	}
}

func TestFirewallHardener_DryRun_ApplyVerifyRollback(t *testing.T) {
	h := hardener.NewFirewallHardenerForTest()
	ctx := context.Background()

	f := scanner.Finding{
		ID:      "fw-002",
		Scanner: "firewall",
		Title:   "Firewall disabled",
	}
	plan := h.Preview(f)

	if err := h.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply (dryRun) returned error: %v", err)
	}
	if err := h.Verify(ctx, plan); err != nil {
		t.Fatalf("Verify (dryRun) returned error: %v", err)
	}
	if err := h.Rollback(ctx, plan); err != nil {
		t.Fatalf("Rollback (dryRun) returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GitHardener tests
// ---------------------------------------------------------------------------

func TestGitHardener_CanFix(t *testing.T) {
	h := hardener.NewGitHardener()

	cases := []struct {
		name    string
		finding scanner.Finding
		want    bool
	}{
		{
			name:    "git_hooks scanner - malicious hook",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Malicious hook detected"},
			want:    true,
		},
		{
			name:    "git_hooks scanner - malicious git hook",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Malicious git hook found"},
			want:    true,
		},
		{
			name:    "git_hooks scanner - suspicious hook",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Suspicious hook in repository"},
			want:    true,
		},
		{
			name:    "git_hooks scanner - hook injection",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Hook injection attempt"},
			want:    true,
		},
		{
			name:    "git_hooks scanner - git hook",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Git hook executes arbitrary code"},
			want:    true,
		},
		{
			name:    "wrong scanner - firewall",
			finding: scanner.Finding{Scanner: "firewall", Title: "Malicious git hook"},
			want:    false,
		},
		{
			name:    "wrong scanner - ssh",
			finding: scanner.Finding{Scanner: "ssh", Title: "Malicious hook"},
			want:    false,
		},
		{
			name:    "git_hooks scanner - unrelated title",
			finding: scanner.Finding{Scanner: "git_hooks", Title: "Untracked repository found"},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.CanFix(tc.finding)
			if got != tc.want {
				t.Errorf("CanFix(%q/%q) = %v, want %v", tc.finding.Scanner, tc.finding.Title, got, tc.want)
			}
		})
	}
}

func TestGitHardener_Preview(t *testing.T) {
	h := hardener.NewGitHardener()

	f := scanner.Finding{
		ID:      "git-001",
		Scanner: "git_hooks",
		Title:   "Malicious git hook detected",
	}

	plan := h.Preview(f)

	if plan.Finding.ID != f.ID {
		t.Errorf("plan.Finding.ID = %q, want %q", plan.Finding.ID, f.ID)
	}

	if plan.Description == "" {
		t.Error("plan.Description is empty")
	}

	// Description should mention hooks and /dev/null.
	if !strings.Contains(strings.ToLower(plan.Description), "hook") {
		t.Error("plan.Description does not mention hooks")
	}

	// Verify core.hooksPath /dev/null action is present.
	hooksPathFound := false
	for _, action := range plan.Actions {
		for i, arg := range action.Args {
			if arg == "core.hooksPath" && i+1 < len(action.Args) && action.Args[i+1] == "/dev/null" {
				hooksPathFound = true
				break
			}
		}
	}
	if !hooksPathFound {
		t.Error("plan.Actions does not include core.hooksPath=/dev/null")
	}

	// Verify fsck settings are included.
	fsckCount := 0
	for _, action := range plan.Actions {
		for _, arg := range action.Args {
			if strings.Contains(arg, "fsckobjects") {
				fsckCount++
				break
			}
		}
	}
	if fsckCount < 3 {
		t.Errorf("plan.Actions contains %d fsckobjects settings, want at least 3", fsckCount)
	}

	// Verify rollback is present.
	if len(plan.Rollback.Steps) == 0 {
		t.Error("plan.Rollback.Steps is empty")
	}

	// Rollback step should mention --unset core.hooksPath.
	unsetFound := false
	for _, step := range plan.Rollback.Steps {
		for _, arg := range step.Action.Args {
			if arg == "--unset" {
				unsetFound = true
				break
			}
		}
	}
	if !unsetFound {
		t.Error("plan.Rollback.Steps does not include --unset action")
	}
}

func TestGitHardener_Name(t *testing.T) {
	h := hardener.NewGitHardener()
	if h.Name() != "git" {
		t.Errorf("Name() = %q, want %q", h.Name(), "git")
	}
}

func TestGitHardener_ApplyAndVerify(t *testing.T) {
	// Use a temporary directory as the git config home to avoid touching
	// the real ~/.gitconfig.
	tmpHome := t.TempDir()
	tmpConfig := filepath.Join(tmpHome, ".gitconfig")

	// Pre-populate an empty config so git doesn't error on missing file.
	if err := os.WriteFile(tmpConfig, []byte("[user]\n\tname = test\n"), 0o600); err != nil {
		t.Fatalf("failed to create temp gitconfig: %v", err)
	}

	t.Setenv("HOME", tmpHome)
	// GIT_CONFIG_GLOBAL overrides --global resolution on git ≥ 2.32.
	t.Setenv("GIT_CONFIG_GLOBAL", tmpConfig)

	h := hardener.NewGitHardener()
	ctx := context.Background()

	f := scanner.Finding{
		ID:      "git-002",
		Scanner: "git_hooks",
		Title:   "Malicious git hook detected",
	}
	plan := h.Preview(f)

	if err := h.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	// Verify the config file contains the expected settings.
	data, err := os.ReadFile(tmpConfig)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "/dev/null") {
		t.Errorf("gitconfig after Apply does not contain /dev/null; got:\n%s", content)
	}

	// Verify via the hardener's Verify method.
	if err := h.Verify(ctx, plan); err != nil {
		t.Errorf("Verify error after Apply: %v", err)
	}
}

func TestGitHardener_Rollback(t *testing.T) {
	tmpHome := t.TempDir()
	tmpConfig := filepath.Join(tmpHome, ".gitconfig")

	if err := os.WriteFile(tmpConfig, []byte("[user]\n\tname = test\n"), 0o600); err != nil {
		t.Fatalf("failed to create temp gitconfig: %v", err)
	}

	t.Setenv("HOME", tmpHome)
	t.Setenv("GIT_CONFIG_GLOBAL", tmpConfig)

	h := hardener.NewGitHardener()
	ctx := context.Background()

	f := scanner.Finding{
		ID:      "git-003",
		Scanner: "git_hooks",
		Title:   "Malicious hook injection",
	}
	plan := h.Preview(f)

	// Apply then rollback.
	if err := h.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	if err := h.Rollback(ctx, plan); err != nil {
		t.Fatalf("Rollback error: %v", err)
	}

	// After rollback, Verify should fail (core.hooksPath is unset).
	if err := h.Verify(ctx, plan); err == nil {
		t.Error("expected Verify to fail after Rollback, but it succeeded")
	}
}
