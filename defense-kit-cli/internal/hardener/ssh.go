package hardener

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// sshDirective maps a canonical SSH directive name to the value that the
// hardener should enforce.
type sshDirective struct {
	directive string
	value     string
}

// knownSSHFixes maps title keywords (lower-case) to the directive+value to
// enforce.
var knownSSHFixes = []struct {
	titleKeyword string
	directive    string
	value        string
}{
	{"permitrootlogin", "PermitRootLogin", "no"},
	{"root login enabled", "PermitRootLogin", "no"},
	{"passwordauthentication", "PasswordAuthentication", "no"},
	{"password authentication enabled", "PasswordAuthentication", "no"},
	{"permitemptypasswords", "PermitEmptyPasswords", "no"},
	{"maxauthtries", "MaxAuthTries", "3"},
}

// SSHHardener remediates SSH configuration findings.
type SSHHardener struct {
	configPath string
}

// NewSSHHardener returns an SSHHardener that targets /etc/ssh/sshd_config.
func NewSSHHardener() *SSHHardener {
	return &SSHHardener{configPath: "/etc/ssh/sshd_config"}
}

// NewSSHHardenerWithConfig returns an SSHHardener that targets the given path.
// Intended for testing.
func NewSSHHardenerWithConfig(path string) *SSHHardener {
	return &SSHHardener{configPath: path}
}

// Name returns "ssh".
func (s *SSHHardener) Name() string { return "ssh" }

// CanFix returns true when the finding comes from the "ssh" scanner and its
// title matches a known fixable directive.
func (s *SSHHardener) CanFix(f scanner.Finding) bool {
	if f.Scanner != "ssh" {
		return false
	}
	lower := strings.ToLower(f.Title)
	for _, fix := range knownSSHFixes {
		if strings.Contains(lower, fix.titleKeyword) {
			return true
		}
	}
	return false
}

// resolve returns the directive and desired value for f, or an empty struct if
// the finding is not handled.
func (s *SSHHardener) resolve(f scanner.Finding) (sshDirective, bool) {
	lower := strings.ToLower(f.Title)
	for _, fix := range knownSSHFixes {
		if strings.Contains(lower, fix.titleKeyword) {
			return sshDirective{directive: fix.directive, value: fix.value}, true
		}
	}
	return sshDirective{}, false
}

// Preview returns a FixPlan describing the change without touching the file.
func (s *SSHHardener) Preview(f scanner.Finding) FixPlan {
	d, ok := s.resolve(f)
	if !ok {
		return FixPlan{Finding: f}
	}

	action := FixAction{
		Type:   FileEdit,
		Target: s.configPath,
		Args:   []string{d.directive, d.value},
	}

	rollbackStep := RollbackStep{
		Description: fmt.Sprintf("Restore %s in %s", d.directive, s.configPath),
		Action:      action,
		Verify:      []string{"grep", d.directive, s.configPath},
	}

	return FixPlan{
		Finding:     f,
		Description: fmt.Sprintf("Set %s to %s in %s", d.directive, d.value, s.configPath),
		Actions:     []FixAction{action},
		BackupPaths: map[string]string{},
		Rollback: RollbackPlan{
			Steps: []RollbackStep{rollbackStep},
		},
	}
}

// Apply reads the sshd_config, replaces or adds the target directive, then
// writes it back.
func (s *SSHHardener) Apply(_ context.Context, plan FixPlan) error {
	if len(plan.Actions) == 0 {
		return fmt.Errorf("ssh hardener: no actions in plan")
	}

	action := plan.Actions[0]
	if len(action.Args) < 2 {
		return fmt.Errorf("ssh hardener: action missing directive/value args")
	}
	directive := action.Args[0]
	value := action.Args[1]

	lines, err := readLines(s.configPath)
	if err != nil {
		return fmt.Errorf("ssh hardener: read %q: %w", s.configPath, err)
	}

	found := false
	newLines := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, "# \t")
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(directive)) {
			newLines = append(newLines, directive+" "+value)
			found = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if !found {
		newLines = append(newLines, directive+" "+value)
	}

	return writeLines(s.configPath, newLines)
}

// Verify re-reads the config and confirms the directive has the expected value.
func (s *SSHHardener) Verify(_ context.Context, plan FixPlan) error {
	if len(plan.Actions) == 0 {
		return fmt.Errorf("ssh hardener: no actions in plan")
	}

	action := plan.Actions[0]
	if len(action.Args) < 2 {
		return fmt.Errorf("ssh hardener: action missing directive/value args")
	}
	directive := action.Args[0]
	wantValue := action.Args[1]

	lines, err := readLines(s.configPath)
	if err != nil {
		return fmt.Errorf("ssh hardener verify: read %q: %w", s.configPath, err)
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(strings.SplitN(trimmed, " ", 2)[0], directive) {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 && strings.EqualFold(parts[1], wantValue) {
				return nil
			}
			return fmt.Errorf("ssh hardener verify: directive %q has unexpected value in line %q", directive, line)
		}
	}

	return fmt.Errorf("ssh hardener verify: directive %q not found in %s", directive, s.configPath)
}

// Rollback restores the config from the backup recorded in plan.BackupPaths.
func (s *SSHHardener) Rollback(_ context.Context, plan FixPlan) error {
	backupPath, ok := plan.BackupPaths[s.configPath]
	if !ok || backupPath == "" {
		return fmt.Errorf("ssh hardener rollback: no backup path for %s", s.configPath)
	}
	return RestoreFile(backupPath, s.configPath)
}

// readLines reads a text file and returns its lines without trailing newlines.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes lines to path, each followed by a newline.
func writeLines(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return w.Flush()
}
