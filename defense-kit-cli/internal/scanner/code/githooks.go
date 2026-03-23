package code

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// standardHookNames are the Git hook files checked for malicious content.
var standardHookNames = []string{
	"pre-commit",
	"post-checkout",
	"post-merge",
	"pre-push",
	"post-receive",
}

// maliciousPatterns are substrings that indicate a hook may be malicious.
var maliciousPatterns = []string{
	"curl",
	"wget",
	" nc ",
	"\tnc ",
	";nc ",
	"|nc ",
	"/dev/tcp",
	"base64",
	"eval",
}

// knownFrameworkSignatures are strings embedded by well-known hook frameworks.
// A hook containing one of these is considered framework-managed.
var knownFrameworkSignatures = []string{
	"husky",
	"pre-commit",    // pre-commit.com framework
	"lefthook",
	"simple-git-hooks",
}

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

// Scan walks TargetPaths looking for .git/hooks/ directories and checks hook
// files for malicious patterns or suspicious executables.
func (s *GitHooksScanner) Scan(_ context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	roots := opts.TargetPaths
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err == nil {
			roots = []string{home}
		}
	}

	var findings []scanner.Finding
	visited := make(map[string]bool)

	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() || info.Name() != "hooks" {
				return nil
			}
			// Ensure the parent directory is named ".git".
			parent := filepath.Base(filepath.Dir(path))
			if parent != ".git" {
				return nil
			}
			if visited[path] {
				return nil
			}
			visited[path] = true

			ff := checkHooksDir(path)
			findings = append(findings, ff...)
			return filepath.SkipDir
		})
	}

	return findings, nil
}

// checkHooksDir inspects all standard hook files in a .git/hooks directory.
func checkHooksDir(hooksDir string) []scanner.Finding {
	var findings []scanner.Finding

	for _, hookName := range standardHookNames {
		hookPath := filepath.Join(hooksDir, hookName)
		info, err := os.Lstat(hookPath)
		if err != nil {
			// Hook file doesn't exist — not a finding.
			continue
		}
		if info.IsDir() {
			continue
		}

		ff := inspectHookFile(hookPath, info)
		findings = append(findings, ff...)
	}

	return findings
}

// inspectHookFile reads a hook file and returns findings for malicious content
// or suspicious executables.
func inspectHookFile(hookPath string, info os.FileInfo) []scanner.Finding {
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return nil
	}

	contentStr := string(content)
	var findings []scanner.Finding

	// Check for malicious patterns.
	for _, pattern := range maliciousPatterns {
		if strings.Contains(contentStr, pattern) {
			loc := hookPath
			title := "Malicious pattern in Git hook"
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("git_hooks", loc, title+":"+pattern),
				Scanner:     "git_hooks",
				Severity:    scanner.SevCritical,
				Title:       title,
				Detail:      fmt.Sprintf("Git hook %q contains the pattern %q, which is commonly used in malicious scripts for reverse shells, exfiltration, or obfuscated execution.", hookPath, pattern),
				Evidence:    extractEvidenceLine(contentStr, pattern),
				Location:    hookPath,
				Remediation: "Review the hook file immediately. If it was not intentionally added, remove it and investigate how it was placed there. Rotate any credentials accessible from the repository.",
				References: []string{
					"https://attack.mitre.org/techniques/T1546/004/",
				},
			})
			// One finding per hook file is enough — break after first match.
			break
		}
	}

	// If no malicious pattern was found, check whether the hook is an unknown executable.
	if len(findings) == 0 {
		isExecutable := info.Mode()&0o111 != 0
		if isExecutable && !isKnownFramework(contentStr) {
			loc := hookPath
			title := "Unknown executable Git hook"
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("git_hooks", loc, title),
				Scanner:     "git_hooks",
				Severity:    scanner.SevMedium,
				Title:       title,
				Detail:      fmt.Sprintf("Git hook %q is executable and does not appear to belong to a known hook management framework (husky, pre-commit, lefthook). Verify it is intentional.", hookPath),
				Evidence:    truncateEvidence(contentStr, 200),
				Location:    hookPath,
				Remediation: "Review the hook file and confirm it was intentionally added by the team. If unexpected, remove it and audit recent repository changes.",
			})
		}
	}

	return findings
}

// isKnownFramework returns true if the hook content contains signatures from a
// well-known hook management framework.
func isKnownFramework(content string) bool {
	lower := strings.ToLower(content)
	for _, sig := range knownFrameworkSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// extractEvidenceLine returns the first line from content that contains the
// given pattern, truncated to 200 characters.
func extractEvidenceLine(content, pattern string) string {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, pattern) {
			return truncateEvidence(strings.TrimSpace(line), 200)
		}
	}
	return truncateEvidence(pattern, 200)
}

// truncateEvidence truncates s to at most maxLen characters.
func truncateEvidence(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
