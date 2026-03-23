package hardener

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// gitCanFixKeywords are lower-case title substrings the git hardener handles.
var gitCanFixKeywords = []string{
	"malicious hook",
	"malicious git hook",
	"suspicious hook",
	"hook injection",
	"git hook",
	"hooks path",
}

// gitHardenConfigs are the git global config settings applied by the hardener.
var gitHardenConfigs = []struct {
	key   string
	value string
}{
	{"core.hooksPath", "/dev/null"},
	{"transfer.fsckobjects", "true"},
	{"receive.fsckobjects", "true"},
	{"fetch.fsckobjects", "true"},
}

// GitHardener remediates Git configuration findings by disabling git hooks
// globally and enabling object integrity checking.
type GitHardener struct{}

// NewGitHardener returns a new GitHardener.
func NewGitHardener() *GitHardener { return &GitHardener{} }

// Name returns "git".
func (g *GitHardener) Name() string { return "git" }

// CanFix returns true when the finding comes from the "git_hooks" scanner and
// its title matches a known fixable keyword.
func (g *GitHardener) CanFix(f scanner.Finding) bool {
	if f.Scanner != "git_hooks" {
		return false
	}
	lower := strings.ToLower(f.Title)
	for _, kw := range gitCanFixKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// Preview returns a FixPlan describing the git config changes.
func (g *GitHardener) Preview(f scanner.Finding) FixPlan {
	actions := make([]FixAction, 0, len(gitHardenConfigs))
	for _, cfg := range gitHardenConfigs {
		actions = append(actions, FixAction{
			Type:   CommandExec,
			Target: "git",
			Args:   []string{"git", "config", "--global", cfg.key, cfg.value},
		})
	}

	rollbackStep := RollbackStep{
		Description: "Unset core.hooksPath from global git config to restore hook execution",
		Action: FixAction{
			Type:   CommandExec,
			Target: "git",
			Args:   []string{"git", "config", "--global", "--unset", "core.hooksPath"},
		},
	}

	return FixPlan{
		Finding: f,
		Description: "Apply global git hardening: disable all hooks by redirecting core.hooksPath " +
			"to /dev/null, and enable fsck object integrity checks for transfer, receive, and fetch.",
		Actions:     actions,
		BackupPaths: map[string]string{},
		Rollback: RollbackPlan{
			Steps: []RollbackStep{rollbackStep},
		},
	}
}

// Apply runs the git config commands to harden the global git configuration.
func (g *GitHardener) Apply(ctx context.Context, _ FixPlan) error {
	for _, cfg := range gitHardenConfigs {
		argv := []string{"git", "config", "--global", cfg.key, cfg.value}
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git hardener: set %s=%s: %w\noutput: %s", cfg.key, cfg.value, err, out)
		}
	}
	return nil
}

// Verify checks that core.hooksPath is set to /dev/null in the global git config.
func (g *GitHardener) Verify(ctx context.Context, _ FixPlan) error {
	cmd := exec.CommandContext(ctx, "git", "config", "--global", "--get", "core.hooksPath")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("git hardener verify: git config --global --get core.hooksPath: %w", err)
	}

	got := strings.TrimSpace(string(out))
	if got != "/dev/null" {
		return fmt.Errorf("git hardener verify: core.hooksPath = %q, want /dev/null", got)
	}

	return nil
}

// Rollback removes core.hooksPath from the global git config.
func (g *GitHardener) Rollback(ctx context.Context, _ FixPlan) error {
	cmd := exec.CommandContext(ctx, "git", "config", "--global", "--unset", "core.hooksPath")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Exit code 5 means the key was not set — treat as success.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
			return nil
		}
		return fmt.Errorf("git hardener rollback: unset core.hooksPath: %w\noutput: %s", err, out)
	}
	return nil
}
