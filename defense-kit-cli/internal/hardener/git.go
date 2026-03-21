package hardener

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// GitHardener is a stub that will eventually remediate Git configuration findings.
type GitHardener struct{}

// NewGitHardener returns a new GitHardener.
func NewGitHardener() *GitHardener { return &GitHardener{} }

// Name returns "git".
func (g *GitHardener) Name() string { return "git" }

// CanFix always returns false — implementation pending.
func (g *GitHardener) CanFix(_ scanner.Finding) bool { return false }

// Preview returns an empty FixPlan.
func (g *GitHardener) Preview(f scanner.Finding) FixPlan { return FixPlan{Finding: f} }

// Apply is a no-op stub.
func (g *GitHardener) Apply(_ context.Context, _ FixPlan) error { return nil }

// Verify is a no-op stub.
func (g *GitHardener) Verify(_ context.Context, _ FixPlan) error { return nil }

// Rollback is a no-op stub.
func (g *GitHardener) Rollback(_ context.Context, _ FixPlan) error { return nil }
