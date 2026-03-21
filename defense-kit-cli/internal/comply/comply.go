package comply

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkCIS   Framework = "cis"
	FrameworkSOC2  Framework = "soc2"
	FrameworkOWASP Framework = "owasp"
)

// Control represents a compliance control/benchmark item.
type Control struct {
	ID        string    // e.g., "CIS-5.2.10"
	Framework Framework // e.g., FrameworkCIS
	Title     string    // e.g., "Ensure SSH root login is disabled"
	Section   string    // e.g., "5.2 SSH Server Configuration"
	Severity  string    // e.g., "Level 1"
}

// ControlMapping maps a scanner finding pattern to one or more compliance controls.
type ControlMapping struct {
	ScannerName  string    // which scanner produces this finding (matches Finding.Scanner)
	TitlePattern string    // regex matched against Finding.Title (case-insensitive)
	Controls     []Control // compliance controls this finding relates to
}

// ComplianceResult shows how findings map to controls for a given framework.
type ComplianceResult struct {
	Framework     Framework
	TotalControls int
	Passed        int
	Failed        int
	NotAssessed   int
	Findings      []ComplianceFinding
}

// ComplianceFinding pairs a scanner finding with the controls it affects.
type ComplianceFinding struct {
	Finding  scanner.Finding
	Controls []Control
	Status   string // "pass", "fail", "not_assessed"
}

// DefaultMappings returns CIS Benchmark mappings for Linux.
// Each entry links a scanner name and title pattern to one or more CIS controls.
func DefaultMappings() []ControlMapping {
	return []ControlMapping{
		// --- SSH ---
		{
			ScannerName:  "ssh",
			TitlePattern: "PermitRootLogin",
			Controls: []Control{
				{
					ID:        "CIS-5.2.10",
					Framework: FrameworkCIS,
					Title:     "Ensure SSH root login is disabled",
					Section:   "5.2 SSH Server Configuration",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "ssh",
			TitlePattern: "PasswordAuthentication",
			Controls: []Control{
				{
					ID:        "CIS-5.2.12",
					Framework: FrameworkCIS,
					Title:     "Ensure SSH PasswordAuthentication is disabled",
					Section:   "5.2 SSH Server Configuration",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "ssh",
			TitlePattern: "PermitEmptyPasswords",
			Controls: []Control{
				{
					ID:        "CIS-5.2.11",
					Framework: FrameworkCIS,
					Title:     "Ensure SSH PermitEmptyPasswords is disabled",
					Section:   "5.2 SSH Server Configuration",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "ssh",
			TitlePattern: "MaxAuthTries",
			Controls: []Control{
				{
					ID:        "CIS-5.2.7",
					Framework: FrameworkCIS,
					Title:     "Ensure SSH MaxAuthTries is set to 4 or less",
					Section:   "5.2 SSH Server Configuration",
					Severity:  "Level 1",
				},
			},
		},

		// --- Filesystem ---
		{
			ScannerName:  "file_integrity",
			TitlePattern: "SUID",
			Controls: []Control{
				{
					ID:        "CIS-6.1.13",
					Framework: FrameworkCIS,
					Title:     "Audit SUID executables",
					Section:   "6.1 System File Permissions",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "capabilities",
			TitlePattern: "SGID",
			Controls: []Control{
				{
					ID:        "CIS-6.1.14",
					Framework: FrameworkCIS,
					Title:     "Audit SGID executables",
					Section:   "6.1 System File Permissions",
					Severity:  "Level 1",
				},
			},
		},

		// --- Persistence / Cron ---
		{
			ScannerName:  "cron",
			TitlePattern: "suspicious cron|cron",
			Controls: []Control{
				{
					ID:        "CIS-5.1",
					Framework: FrameworkCIS,
					Title:     "Configure cron",
					Section:   "5.1 Configure cron",
					Severity:  "Level 1",
				},
			},
		},

		// --- Users ---
		{
			ScannerName:  "users",
			TitlePattern: "UID 0|uid 0|root uid",
			Controls: []Control{
				{
					ID:        "CIS-6.2.1",
					Framework: FrameworkCIS,
					Title:     "Ensure accounts with UID 0 are only root",
					Section:   "6.2 User and Group Settings",
					Severity:  "Level 1",
				},
			},
		},

		// --- Network / Firewall ---
		{
			ScannerName:  "firewall",
			TitlePattern: "iptables|firewall|nftables",
			Controls: []Control{
				{
					ID:        "CIS-3.5",
					Framework: FrameworkCIS,
					Title:     "Firewall Configuration",
					Section:   "3.5 Firewall Configuration",
					Severity:  "Level 1",
				},
			},
		},

		// --- System / Rootkit ---
		{
			ScannerName:  "rootkit",
			TitlePattern: "kernel module|rootkit",
			Controls: []Control{
				{
					ID:        "CIS-1.1",
					Framework: FrameworkCIS,
					Title:     "Filesystem Configuration",
					Section:   "1.1 Filesystem Configuration",
					Severity:  "Level 1",
				},
			},
		},

		// --- Environment ---
		{
			ScannerName:  "shell_rc",
			TitlePattern: "RC poisoning|shell rc|bashrc|profile",
			Controls: []Control{
				{
					ID:        "CIS-5.4.4",
					Framework: FrameworkCIS,
					Title:     "Ensure default user shell timeout is configured",
					Section:   "5.4 User Accounts and Environment",
					Severity:  "Level 2",
				},
			},
		},
		{
			ScannerName:  "env_vars",
			TitlePattern: "PATH|env var",
			Controls: []Control{
				{
					ID:        "CIS-6.2.6",
					Framework: FrameworkCIS,
					Title:     "Ensure root PATH Integrity",
					Section:   "6.2 User and Group Settings",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "ld_preload",
			TitlePattern: "LD_PRELOAD|preload",
			Controls: []Control{
				{
					ID:        "CIS-1.5.4",
					Framework: FrameworkCIS,
					Title:     "Ensure prelink is not installed",
					Section:   "1.5 Additional Process Hardening",
					Severity:  "Level 1",
				},
			},
		},
		{
			ScannerName:  "pam",
			TitlePattern: "PAM|pam module",
			Controls: []Control{
				{
					ID:        "CIS-5.3",
					Framework: FrameworkCIS,
					Title:     "Configure PAM",
					Section:   "5.3 Configure PAM",
					Severity:  "Level 1",
				},
			},
		},

		// --- Code / Credentials ---
		{
			ScannerName:  "credentials",
			TitlePattern: "leaked secret|secret|credential|password|api key|token",
			Controls: []Control{
				{
					ID:        "CIS-5.4.1",
					Framework: FrameworkCIS,
					Title:     "Ensure password creation requirements are configured",
					Section:   "5.4 User Accounts and Environment",
					Severity:  "Level 1",
				},
			},
		},

		// --- Network / Ports ---
		{
			ScannerName:  "ports",
			TitlePattern: "open port|listening port|unexpected port",
			Controls: []Control{
				{
					ID:        "CIS-3.4",
					Framework: FrameworkCIS,
					Title:     "Uncommon Network Protocols",
					Section:   "3.4 Uncommon Network Protocols",
					Severity:  "Level 2",
				},
			},
		},
	}
}

// compiledMapping is DefaultMappings with pre-compiled regular expressions.
type compiledMapping struct {
	ControlMapping
	re *regexp.Regexp
}

// compileDefaultMappings compiles the title patterns from DefaultMappings into regexps.
func compileDefaultMappings() []compiledMapping {
	raw := DefaultMappings()
	out := make([]compiledMapping, 0, len(raw))
	for _, m := range raw {
		re, err := regexp.Compile("(?i)" + m.TitlePattern)
		if err != nil {
			// Fallback: treat pattern as a literal string
			re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(m.TitlePattern))
		}
		out = append(out, compiledMapping{ControlMapping: m, re: re})
	}
	return out
}

// collectUniqueControls gathers a de-duplicated list of controls from all mappings.
func collectUniqueControls(mappings []compiledMapping, framework Framework) []Control {
	seen := make(map[string]struct{})
	var controls []Control
	for _, m := range mappings {
		for _, c := range m.Controls {
			if c.Framework != framework {
				continue
			}
			if _, ok := seen[c.ID]; ok {
				continue
			}
			seen[c.ID] = struct{}{}
			controls = append(controls, c)
		}
	}
	return controls
}

// MapFindings maps scan findings to compliance controls for the given framework.
// Each finding that matches a mapping is marked "fail"; all unique controls that
// have no matching finding are counted as "not_assessed".
func MapFindings(findings []scanner.Finding, framework Framework) ComplianceResult {
	mappings := compileDefaultMappings()

	// Build the full set of unique controls for this framework.
	allControls := collectUniqueControls(mappings, framework)

	// For each finding, determine which controls it violates.
	failedControlIDs := make(map[string]struct{})
	var complianceFindings []ComplianceFinding

	for _, f := range findings {
		var matched []Control
		for _, m := range mappings {
			if m.ScannerName != f.Scanner {
				continue
			}
			if !m.re.MatchString(f.Title) {
				continue
			}
			for _, c := range m.Controls {
				if c.Framework == framework {
					matched = append(matched, c)
					failedControlIDs[c.ID] = struct{}{}
				}
			}
		}

		status := "not_assessed"
		if len(matched) > 0 {
			status = "fail"
		}

		complianceFindings = append(complianceFindings, ComplianceFinding{
			Finding:  f,
			Controls: matched,
			Status:   status,
		})
	}

	failed := len(failedControlIDs)
	notAssessed := len(allControls) - failed
	if notAssessed < 0 {
		notAssessed = 0
	}

	return ComplianceResult{
		Framework:     framework,
		TotalControls: len(allControls),
		Passed:        0, // scan findings are violations; no positive confirmation of passing
		Failed:        failed,
		NotAssessed:   notAssessed,
		Findings:      complianceFindings,
	}
}

// FormatReport returns a human-readable compliance report string.
func FormatReport(result ComplianceResult) string {
	var sb strings.Builder

	frameworkLabel := strings.ToUpper(string(result.Framework))

	sb.WriteString(fmt.Sprintf("=== Compliance Report: %s ===\n\n", frameworkLabel))
	sb.WriteString(fmt.Sprintf("Total Controls:  %d\n", result.TotalControls))
	sb.WriteString(fmt.Sprintf("  Pass:          %d\n", result.Passed))
	sb.WriteString(fmt.Sprintf("  Fail:          %d\n", result.Failed))
	sb.WriteString(fmt.Sprintf("  Not Assessed:  %d\n\n", result.NotAssessed))

	if len(result.Findings) == 0 {
		sb.WriteString("No findings to report.\n")
		return sb.String()
	}

	sb.WriteString("--- Findings ---\n")
	for _, cf := range result.Findings {
		status := strings.ToUpper(cf.Status)
		sb.WriteString(fmt.Sprintf("\n[%s] [%s] %s\n",
			status,
			cf.Finding.Severity.String(),
			cf.Finding.Title,
		))
		if len(cf.Controls) > 0 {
			sb.WriteString("  Mapped Controls:\n")
			for _, c := range cf.Controls {
				sb.WriteString(fmt.Sprintf("    - %s: %s (%s)\n", c.ID, c.Title, c.Severity))
			}
		}
	}

	return sb.String()
}
