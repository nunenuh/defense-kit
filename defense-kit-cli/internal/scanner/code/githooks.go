package code

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// GitHooksScanner checks for malicious or tampered Git hooks.
type GitHooksScanner struct{}

// NewGitHooksScanner creates a new GitHooksScanner.
func NewGitHooksScanner() *GitHooksScanner {
	return &GitHooksScanner{}
}

func (s *GitHooksScanner) Name() string            { return "git_hooks" }
func (s *GitHooksScanner) Category() string        { return "code" }
func (s *GitHooksScanner) RequiresRoot() bool      { return false }
func (s *GitHooksScanner) RequiredTools() []string { return nil }
func (s *GitHooksScanner) OptionalTools() []string { return nil }
func (s *GitHooksScanner) Available() bool         { return true }
func (s *GitHooksScanner) Description() string {
	return "Checks Git hook scripts for malicious commands such as reverse shells, data exfiltration, and obfuscated payloads that execute on developer actions."
}

// Scan is a stub — not yet implemented.
func (s *GitHooksScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
