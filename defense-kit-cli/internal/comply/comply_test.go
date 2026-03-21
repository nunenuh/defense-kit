package comply_test

import (
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/comply"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// TestDefaultMappings verifies mappings exist for the major scanner categories.
func TestDefaultMappings(t *testing.T) {
	mappings := comply.DefaultMappings()
	if len(mappings) == 0 {
		t.Fatal("DefaultMappings returned empty slice")
	}

	// Categories that must have at least one mapping
	requiredScanners := []string{"ssh", "file_integrity", "users", "firewall", "credentials", "ports"}
	scannerSet := make(map[string]bool)
	for _, m := range mappings {
		scannerSet[m.ScannerName] = true
	}

	for _, name := range requiredScanners {
		if !scannerSet[name] {
			t.Errorf("missing mapping for scanner %q", name)
		}
	}

	// Every mapping must have at least one control
	for i, m := range mappings {
		if len(m.Controls) == 0 {
			t.Errorf("mapping[%d] (scanner=%q, pattern=%q) has no controls", i, m.ScannerName, m.TitlePattern)
		}
		for j, c := range m.Controls {
			if c.ID == "" {
				t.Errorf("mapping[%d] control[%d]: empty ID", i, j)
			}
			if c.Title == "" {
				t.Errorf("mapping[%d] control[%d]: empty Title", i, j)
			}
			if c.Framework == "" {
				t.Errorf("mapping[%d] control[%d]: empty Framework", i, j)
			}
		}
	}
}

// TestMapFindings_CIS verifies that SSH findings get mapped to CIS controls.
func TestMapFindings_CIS(t *testing.T) {
	findings := []scanner.Finding{
		{
			ID:       "ssh-001",
			Scanner:  "ssh",
			Severity: scanner.SevHigh,
			Title:    "PermitRootLogin is enabled",
			Detail:   "SSH allows root login",
		},
		{
			ID:       "ssh-002",
			Scanner:  "ssh",
			Severity: scanner.SevHigh,
			Title:    "PasswordAuthentication is enabled",
			Detail:   "SSH allows password authentication",
		},
		{
			ID:       "ssh-003",
			Scanner:  "ssh",
			Severity: scanner.SevMedium,
			Title:    "PermitEmptyPasswords enabled",
			Detail:   "SSH allows empty passwords",
		},
	}

	result := comply.MapFindings(findings, comply.FrameworkCIS)

	if result.Framework != comply.FrameworkCIS {
		t.Errorf("expected framework %q, got %q", comply.FrameworkCIS, result.Framework)
	}

	if result.TotalControls <= 0 {
		t.Error("expected TotalControls > 0")
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one ComplianceFinding")
	}

	// All three SSH findings should be mapped and marked as failed
	failedCount := 0
	for _, cf := range result.Findings {
		if cf.Status == "fail" {
			failedCount++
			if len(cf.Controls) == 0 {
				t.Errorf("finding %q marked fail but has no controls", cf.Finding.Title)
			}
		}
	}
	if failedCount == 0 {
		t.Error("expected at least one failed compliance finding")
	}

	// Failed count should match what the result reports
	if result.Failed != failedCount {
		t.Errorf("result.Failed=%d but counted %d failed findings", result.Failed, failedCount)
	}
}

// TestMapFindings_EmptyFindings verifies that no findings results in all controls being not_assessed.
func TestMapFindings_EmptyFindings(t *testing.T) {
	result := comply.MapFindings(nil, comply.FrameworkCIS)

	if result.Framework != comply.FrameworkCIS {
		t.Errorf("expected framework %q, got %q", comply.FrameworkCIS, result.Framework)
	}

	if result.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Failed)
	}

	if result.Passed != 0 {
		t.Errorf("expected 0 passed, got %d", result.Passed)
	}

	if result.NotAssessed <= 0 {
		t.Error("expected NotAssessed > 0 when no findings are provided")
	}

	if result.TotalControls != result.NotAssessed {
		t.Errorf("with no findings: TotalControls=%d should equal NotAssessed=%d",
			result.TotalControls, result.NotAssessed)
	}
}

// TestFormatReport verifies that the formatted report contains the framework name and counts.
func TestFormatReport(t *testing.T) {
	findings := []scanner.Finding{
		{
			ID:      "ssh-001",
			Scanner: "ssh",
			Title:   "PermitRootLogin is enabled",
		},
	}

	result := comply.MapFindings(findings, comply.FrameworkCIS)
	report := comply.FormatReport(result)

	if report == "" {
		t.Fatal("FormatReport returned empty string")
	}

	// Report must mention the framework
	if !strings.Contains(strings.ToUpper(report), "CIS") {
		t.Error("report does not mention the CIS framework")
	}

	// Report must contain pass/fail counts
	requiredFields := []string{"Pass", "Fail", "Total"}
	for _, field := range requiredFields {
		if !strings.Contains(report, field) {
			t.Errorf("report missing field %q", field)
		}
	}
}

// TestFrameworkConstants verifies the framework constants have the expected values.
func TestFrameworkConstants(t *testing.T) {
	if comply.FrameworkCIS != "cis" {
		t.Errorf("FrameworkCIS = %q, want %q", comply.FrameworkCIS, "cis")
	}
	if comply.FrameworkSOC2 != "soc2" {
		t.Errorf("FrameworkSOC2 = %q, want %q", comply.FrameworkSOC2, "soc2")
	}
	if comply.FrameworkOWASP != "owasp" {
		t.Errorf("FrameworkOWASP = %q, want %q", comply.FrameworkOWASP, "owasp")
	}
}
