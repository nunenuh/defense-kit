package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// keyAuditRules lists audit rule keywords whose presence in auditctl output
// indicates important security monitoring is in place.
var keyAuditRules = []struct {
	keyword     string
	description string
}{
	{keyword: "/etc/passwd", description: "file watch on /etc/passwd"},
	{keyword: "/etc/shadow", description: "file watch on /etc/shadow"},
	{keyword: "modules", description: "kernel module loading"},
	{keyword: "execve", description: "privilege escalation via execve"},
	{keyword: "setuid", description: "setuid system calls"},
}

// AuditdScanner checks whether the Linux Audit Daemon (auditd) is running
// and whether meaningful audit rules are configured.
type AuditdScanner struct {
	procPath string
}

// NewAuditdScanner creates an AuditdScanner with production defaults.
func NewAuditdScanner() *AuditdScanner {
	return &AuditdScanner{procPath: "/proc"}
}

// NewAuditdScannerWithPath creates an AuditdScanner with a custom /proc path
// (used in tests).
func NewAuditdScannerWithPath(procPath string) *AuditdScanner {
	return &AuditdScanner{procPath: procPath}
}

func (s *AuditdScanner) Name() string            { return "auditd" }
func (s *AuditdScanner) Category() string        { return "system" }
func (s *AuditdScanner) RequiresRoot() bool      { return true }
func (s *AuditdScanner) RequiredTools() []string { return nil }
func (s *AuditdScanner) OptionalTools() []string { return []string{"auditctl"} }
func (s *AuditdScanner) Available() bool         { return true }
func (s *AuditdScanner) Description() string {
	return "Checks whether auditd is running and whether key audit rules (passwd, shadow, module loads, privilege escalation) are configured."
}

// Scan checks auditd presence and rule coverage.
func (s *AuditdScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	running := s.isAuditdRunning()
	if !running {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), s.procPath, "auditd not running"),
			Scanner:  s.Name(),
			Severity: scanner.SevHigh,
			Title:    "auditd is not running",
			Detail:   "The Linux Audit Daemon (auditd) is not running. Without auditd, security-relevant events (authentication attempts, file access, privilege escalation) are not logged to the audit trail.",
			Evidence: "auditd process not found in /proc",
			Location: s.procPath,
			Remediation: "Install and start auditd: run 'apt install auditd' followed by 'systemctl enable --now auditd'. Configure appropriate audit rules in /etc/audit/rules.d/.",
			References: []string{
				"https://www.redhat.com/sysadmin/configure-linux-auditing-auditd",
				"https://www.cisecurity.org/benchmark/ubuntu_linux",
			},
		})
		// If auditd is not running, rule checks are moot.
		return findings, nil
	}

	// auditd is running — check rule coverage via auditctl if available.
	ruleFindings := s.checkAuditRules(ctx, opts)
	findings = append(findings, ruleFindings...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// isAuditdRunning checks /proc for a process whose comm is "auditd".
func (s *AuditdScanner) isAuditdRunning() bool {
	entries, err := os.ReadDir(s.procPath)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		commPath := filepath.Join(s.procPath, entry.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == "auditd" {
			return true
		}
	}
	return false
}

// checkAuditRules uses auditctl to list active rules and flags missing
// important rule categories.
func (s *AuditdScanner) checkAuditRules(ctx context.Context, opts scanner.ScanOptions) []scanner.Finding {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("auditctl") {
		return nil
	}

	out, err := opts.ToolRunner.Run(ctx, "auditctl", []string{"-l"})
	if err != nil && len(out) == 0 {
		return nil
	}

	rulesText := string(out)

	// If no rules are configured at all, emit a MEDIUM finding.
	trimmed := strings.TrimSpace(rulesText)
	if trimmed == "" || trimmed == "No rules" || strings.Contains(trimmed, "No rules") {
		return []scanner.Finding{
			{
				ID:       scanner.GenerateFindingID(s.Name(), "auditctl", "no audit rules configured"),
				Scanner:  s.Name(),
				Severity: scanner.SevMedium,
				Title:    "auditd is running but no audit rules are configured",
				Detail:   "auditd is active but 'auditctl -l' reports no rules. Without rules, no events are captured and the audit trail is empty.",
				Evidence: fmt.Sprintf("auditctl -l output: %q", trimmed),
				Location: "auditctl",
				Remediation: "Add audit rules covering critical files and system calls. A good starting point is the CIS benchmark rules in /etc/audit/rules.d/.",
				References: []string{
					"https://www.cisecurity.org/benchmark/ubuntu_linux",
				},
			},
		}
	}

	// Check for presence of key audit rules.
	var findings []scanner.Finding
	for _, rule := range keyAuditRules {
		if !strings.Contains(rulesText, rule.keyword) {
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID(s.Name(), "auditctl", "missing rule: "+rule.keyword),
				Scanner:  s.Name(),
				Severity: scanner.SevMedium,
				Title:    fmt.Sprintf("Audit rule missing: %s", rule.description),
				Detail: fmt.Sprintf(
					"No audit rule covering %q was found in 'auditctl -l' output. Monitoring for this event is recommended by the CIS Benchmark.",
					rule.keyword,
				),
				Evidence:    fmt.Sprintf("keyword %q not found in audit rules", rule.keyword),
				Location:    "auditctl",
				Remediation: fmt.Sprintf("Add an audit rule for %s. See /etc/audit/rules.d/ and CIS Benchmark section 4.", rule.keyword),
				References: []string{
					"https://www.cisecurity.org/benchmark/ubuntu_linux",
				},
			})
		}
	}

	return findings
}
