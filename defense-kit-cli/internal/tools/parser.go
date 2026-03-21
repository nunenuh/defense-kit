package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// truncate returns s truncated to at most max runes, appending "…" if truncated.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// ── Gitleaks ──────────────────────────────────────────────────────────────────

type gitleaksFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
	RuleID      string `json:"RuleID"`
}

// ParseGitleaksJSON parses the JSON array produced by `gitleaks detect --report-format json`.
// Every finding maps to severity CRITICAL.
func ParseGitleaksJSON(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var raw []gitleaksFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gitleaks: JSON parse error: %w", err)
	}

	findings := make([]scanner.Finding, 0, len(raw))
	for _, r := range raw {
		location := fmt.Sprintf("%s:%d", r.File, r.StartLine)
		title := r.Description
		if title == "" {
			title = r.RuleID
		}
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("gitleaks", location, title),
			Scanner:  "gitleaks",
			Severity: scanner.SevCritical,
			Title:    title,
			Detail:   truncate(r.Match, 256),
			Evidence: truncate(r.Secret, 64),
			Location: location,
			Metadata: map[string]string{
				"rule_id": r.RuleID,
			},
		})
	}
	return findings, nil
}

// ── Trivy ─────────────────────────────────────────────────────────────────────

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

func trivySeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SevCritical
	case "HIGH":
		return scanner.SevHigh
	case "MEDIUM":
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

// ParseTrivyJSON parses the JSON report produced by `trivy image --format json`.
func ParseTrivyJSON(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: JSON parse error: %w", err)
	}

	var findings []scanner.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			location := fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion)
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}
			remediation := ""
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Upgrade to %s", v.FixedVersion)
			}
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("trivy", location, v.VulnerabilityID),
				Scanner:     "trivy",
				Severity:    trivySeverity(v.Severity),
				Title:       title,
				Detail:      truncate(v.Description, 512),
				Location:    location,
				Remediation: remediation,
				Metadata: map[string]string{
					"vuln_id":           v.VulnerabilityID,
					"installed_version": v.InstalledVersion,
					"fixed_version":     v.FixedVersion,
				},
			})
		}
	}
	return findings, nil
}

// ── rkhunter ──────────────────────────────────────────────────────────────────

var rkhunterLine = regexp.MustCompile(`(.+?)\s+\[\s*(Warning|Infected)\s*\]`)

// ParseRkhunterOutput parses the plain-text output of `rkhunter --check`.
// Lines containing `[ Warning ]` map to HIGH; `[ Infected ]` maps to CRITICAL.
func ParseRkhunterOutput(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var findings []scanner.Finding
	for _, line := range strings.Split(string(data), "\n") {
		m := rkhunterLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		check := strings.TrimSpace(m[1])
		level := m[2]

		var sev scanner.Severity
		switch level {
		case "Infected":
			sev = scanner.SevCritical
		default:
			sev = scanner.SevHigh
		}

		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("rkhunter", check, check),
			Scanner:  "rkhunter",
			Severity: sev,
			Title:    check,
			Detail:   strings.TrimSpace(line),
			Location: check,
			Metadata: map[string]string{
				"status": level,
			},
		})
	}
	return findings, nil
}

// ── ssh-audit ─────────────────────────────────────────────────────────────────

type sshAuditReport struct {
	Banner struct {
		Raw string `json:"raw"`
	} `json:"banner"`
	Recommendations []sshAuditRec `json:"recommendations"`
}

type sshAuditRec struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Severity string `json:"severity"`
}

func sshAuditSeverity(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "fail":
		return scanner.SevHigh
	case "warn":
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

// ParseSSHAuditJSON parses the JSON report produced by `ssh-audit --json`.
func ParseSSHAuditJSON(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var report sshAuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("ssh-audit: JSON parse error: %w", err)
	}

	var findings []scanner.Finding
	for _, rec := range report.Recommendations {
		title := rec.Key
		if title == "" {
			title = rec.Value
		}
		location := "ssh-server"
		if report.Banner.Raw != "" {
			location = report.Banner.Raw
		}
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("ssh-audit", location, title),
			Scanner:  "ssh-audit",
			Severity: sshAuditSeverity(rec.Severity),
			Title:    title,
			Detail:   rec.Value,
			Location: location,
			Metadata: map[string]string{
				"key":      rec.Key,
				"severity": rec.Severity,
			},
		})
	}
	return findings, nil
}
