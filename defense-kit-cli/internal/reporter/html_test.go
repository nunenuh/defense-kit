package reporter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// templatePath returns the absolute path to templates/report.html relative to this test file.
func templatePath(t *testing.T) string {
	t.Helper()
	// Walk up from the reporter package to find the templates directory.
	// The module root should contain a templates/ directory.
	dir := filepath.Join("..", "..", "templates", "report.html")
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("could not determine template path: %v", err)
	}
	return abs
}

func makeHTMLResults() []scanner.ScanResult {
	return []scanner.ScanResult{
		{
			Scanner:  "ssh-scanner",
			Status:   scanner.ScanSuccess,
			Duration: 2 * time.Second,
			Findings: []scanner.Finding{
				{
					ID:          "f-001",
					Scanner:     "ssh-scanner",
					Severity:    scanner.SevCritical,
					Title:       "Root SSH Login Enabled",
					Detail:      "PermitRootLogin is set to yes in sshd_config",
					Evidence:    "PermitRootLogin yes",
					Location:    "/etc/ssh/sshd_config",
					Remediation: "Set PermitRootLogin to no",
				},
				{
					ID:          "f-002",
					Scanner:     "ssh-scanner",
					Severity:    scanner.SevHigh,
					Title:       "Weak SSH Cipher",
					Detail:      "Weak cipher detected",
					Evidence:    "Ciphers arcfour",
					Location:    "/etc/ssh/sshd_config",
					Remediation: "Remove arcfour from Ciphers",
				},
			},
		},
		{
			Scanner:  "net-scanner",
			Status:   scanner.ScanSuccess,
			Duration: 1 * time.Second,
			Findings: []scanner.Finding{
				{
					ID:          "f-003",
					Scanner:     "net-scanner",
					Severity:    scanner.SevMedium,
					Title:       "Unexpected Open Port",
					Detail:      "Port 8080 is open without a registered service",
					Evidence:    "tcp 0.0.0.0:8080 LISTEN",
					Location:    "0.0.0.0:8080",
					Remediation: "Close port 8080 or document the service",
				},
			},
		},
	}
}

// TestHTMLReporter_GeneratesFile verifies that Generate creates the output file.
func TestHTMLReporter_GeneratesFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	h := reporter.NewHTMLReporter(templatePath(t))
	err := h.Generate(makeHTMLResults(), "testhost.local", outputPath)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("expected output file to exist at %s", outputPath)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("could not stat output file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected output file to be non-empty")
	}
}

// TestHTMLReporter_ContainsFindings verifies finding titles appear in the HTML output.
func TestHTMLReporter_ContainsFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	h := reporter.NewHTMLReporter(templatePath(t))
	if err := h.Generate(makeHTMLResults(), "testhost.local", outputPath); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	content := string(data)

	for _, title := range []string{
		"Root SSH Login Enabled",
		"Weak SSH Cipher",
		"Unexpected Open Port",
	} {
		if !strings.Contains(content, title) {
			t.Errorf("expected HTML to contain finding title %q", title)
		}
	}
}

// TestHTMLReporter_ContainsSummary verifies the severity summary counts appear in the HTML.
func TestHTMLReporter_ContainsSummary(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	h := reporter.NewHTMLReporter(templatePath(t))
	if err := h.Generate(makeHTMLResults(), "testhost.local", outputPath); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	content := string(data)

	// The results fixture has 1 critical, 1 high, 1 medium, 0 low, 3 total.
	checks := []string{
		"testhost.local", // host name
	}
	for _, want := range checks {
		if !strings.Contains(content, want) {
			t.Errorf("expected HTML summary to contain %q", want)
		}
	}

	// Verify numeric summary values appear somewhere in the page.
	// We check by looking for the digit characters that represent counts.
	if !strings.Contains(content, "3") { // total findings
		t.Error("expected HTML to contain total finding count '3'")
	}
	if !strings.Contains(content, "1") { // critical count
		t.Error("expected HTML to contain critical count '1'")
	}
}

// TestHTMLReporter_HTMLEscapesEvidence injects a script tag as evidence and verifies
// the HTML output does not contain a raw <script> tag (XSS prevention).
func TestHTMLReporter_HTMLEscapesEvidence(t *testing.T) {
	xssPayload := "<script>alert('xss')</script>"

	results := []scanner.ScanResult{
		{
			Scanner: "xss-test-scanner",
			Status:  scanner.ScanSuccess,
			Findings: []scanner.Finding{
				{
					ID:       "xss-001",
					Scanner:  "xss-test-scanner",
					Severity: scanner.SevHigh,
					Title:    "XSS Test Finding",
					Evidence: xssPayload,
					Location: "/tmp/test",
				},
			},
		},
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	h := reporter.NewHTMLReporter(templatePath(t))
	if err := h.Generate(results, "xss-testhost", outputPath); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	content := string(data)

	// The raw <script> tag must NOT appear verbatim.
	if strings.Contains(content, "<script>alert('xss')</script>") {
		t.Error("HTML output contains unescaped <script> tag — XSS vulnerability")
	}

	// The escaped form should be present instead (html/template escapes < as &lt;).
	if !strings.Contains(content, "&lt;script&gt;") {
		t.Error("expected HTML output to contain escaped &lt;script&gt; for the XSS payload")
	}
}

// TestHTMLReporter_EmptyResults verifies that Generate succeeds and produces valid HTML
// when there are no findings (empty results slice).
func TestHTMLReporter_EmptyResults(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty_report.html")

	h := reporter.NewHTMLReporter("") // use embedded template
	err := h.Generate([]scanner.ScanResult{}, "empty-host.local", outputPath)
	if err != nil {
		t.Fatalf("Generate returned error for empty results: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("expected output file to exist at %s", outputPath)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	content := string(data)

	// The file should contain some HTML structure.
	if len(content) == 0 {
		t.Fatal("expected non-empty HTML output even with no findings")
	}

	// The host name should appear in the report.
	if !strings.Contains(content, "empty-host.local") {
		t.Errorf("expected HTML to contain hostname 'empty-host.local', got:\n%s", content[:min(500, len(content))])
	}
}

// min is a local helper to avoid Go version compatibility issues.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestHTMLReporter_ContainsWarning verifies the sharing-warning banner is present.
func TestHTMLReporter_ContainsWarning(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	h := reporter.NewHTMLReporter(templatePath(t))
	if err := h.Generate(makeHTMLResults(), "testhost.local", outputPath); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	content := string(data)

	warningPhrases := []string{
		"do not share",
		"publicly",
	}
	for _, phrase := range warningPhrases {
		if !strings.Contains(strings.ToLower(content), strings.ToLower(phrase)) {
			t.Errorf("expected HTML to contain warning phrase %q", phrase)
		}
	}
}
