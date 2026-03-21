package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// PAMScanner scans /etc/pam.d/ configuration files for suspicious PAM modules.
type PAMScanner struct{}

// NewPAMScanner creates a new PAMScanner.
func NewPAMScanner() *PAMScanner {
	return &PAMScanner{}
}

func (s *PAMScanner) Name() string           { return "pam" }
func (s *PAMScanner) Category() string       { return "environment" }
func (s *PAMScanner) RequiresRoot() bool     { return true }
func (s *PAMScanner) RequiredTools() []string { return nil }
func (s *PAMScanner) OptionalTools() []string { return nil }
func (s *PAMScanner) Available() bool        { return os.Geteuid() == 0 }
func (s *PAMScanner) Description() string {
	return "Scans /etc/pam.d/ configuration files for dangerous PAM modules such as pam_exec.so, pam_script.so, and pam_permit.so in auth context."
}

// pamModuleRule defines how to flag a specific PAM module.
type pamModuleRule struct {
	module      string
	authContext bool // if true, apply CRITICAL only when context is "auth"
	severity    scanner.Severity
	title       string
	detail      string
	remediation string
}

var pamRules = []pamModuleRule{
	{
		module:   "pam_exec.so",
		severity: scanner.SevHigh,
		title:    "pam_exec.so module found",
		detail:   "pam_exec.so executes arbitrary commands during PAM events and is commonly used for backdoors.",
		remediation: "Remove pam_exec.so from PAM configuration unless it is explicitly required and audited.",
	},
	{
		module:   "pam_script.so",
		severity: scanner.SevHigh,
		title:    "pam_script.so module found",
		detail:   "pam_script.so runs scripts during PAM authentication events and can be abused for persistence.",
		remediation: "Remove pam_script.so from PAM configuration unless it is explicitly required and audited.",
	},
	{
		module:      "pam_permit.so",
		authContext: true,
		severity:    scanner.SevHigh, // elevated to CRITICAL when context == "auth"
		title:       "pam_permit.so module found",
		detail:      "pam_permit.so unconditionally permits access; in an auth context this bypasses authentication entirely.",
		remediation: "Remove pam_permit.so from auth stacks; it should never appear in authentication configuration.",
	},
}

// Scan inspects all files in /etc/pam.d/ for dangerous modules.
func (s *PAMScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return scanPAMDir("/etc/pam.d")
}

// scanPAMDir scans all files in the given PAM configuration directory.
func scanPAMDir(dir string) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pam: cannot read %s: %w", dir, err)
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		ff, err := scanPAMFile(path)
		if err != nil {
			// Unreadable file — skip.
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// scanPAMFile scans a single PAM configuration file for suspicious modules.
func scanPAMFile(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding
	lineNum := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// PAM line format: <type> <control> <module-path> [module-arguments]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pamType := strings.ToLower(fields[0])
		modulePath := fields[2]
		// Module names may include a path prefix; compare only the basename.
		moduleName := filepath.Base(modulePath)

		for _, rule := range pamRules {
			if !strings.EqualFold(moduleName, rule.module) {
				continue
			}

			sev := rule.severity
			if rule.authContext && pamType == "auth" {
				sev = scanner.SevCritical
			}

			location := fmt.Sprintf("%s:%d", path, lineNum)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("pam", location, rule.title),
				Scanner:     "pam",
				Severity:    sev,
				Title:       rule.title,
				Detail:      rule.detail,
				Evidence:    line,
				Location:    location,
				Remediation: rule.remediation,
			})
		}
	}
	return findings, sc.Err()
}
