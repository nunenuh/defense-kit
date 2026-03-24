package tools

import (
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ── Gitleaks ──────────────────────────────────────────────────────────────────

const gitleaksSample = `[
  {
    "Description": "AWS Access Key",
    "StartLine": 12,
    "File": "config/settings.py",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "RuleID": "aws-access-key-id"
  }
]`

func TestParseGitleaksJSON_OneAWSKey(t *testing.T) {
	findings, err := ParseGitleaksJSON([]byte(gitleaksSample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != scanner.SevCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Scanner != "gitleaks" {
		t.Errorf("expected scanner=gitleaks, got %s", f.Scanner)
	}
	if f.Location != "config/settings.py:12" {
		t.Errorf("unexpected location: %s", f.Location)
	}
	if f.ID == "" {
		t.Error("finding ID must not be empty")
	}
}

func TestParseGitleaksJSON_Empty(t *testing.T) {
	findings, err := ParseGitleaksJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error on empty input: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty input, got %d", len(findings))
	}

	findings2, err2 := ParseGitleaksJSON([]byte("[]"))
	if err2 != nil {
		t.Fatalf("unexpected error on empty array: %v", err2)
	}
	if len(findings2) != 0 {
		t.Errorf("expected 0 findings for empty array, got %d", len(findings2))
	}
}

func TestParseGitleaksJSON_InvalidJSON(t *testing.T) {
	_, err := ParseGitleaksJSON([]byte("{not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ── Trivy ─────────────────────────────────────────────────────────────────────

const trivySample = `{
  "Results": [
    {
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-44487",
          "PkgName": "golang.org/x/net",
          "InstalledVersion": "0.10.0",
          "FixedVersion": "0.17.0",
          "Severity": "HIGH",
          "Title": "HTTP/2 Rapid Reset Attack",
          "Description": "The HTTP/2 protocol allows a denial of service via rapid stream resets."
        }
      ]
    }
  ]
}`

func TestParseTrivyJSON_OneHighVuln(t *testing.T) {
	findings, err := ParseTrivyJSON([]byte(trivySample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != scanner.SevHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Scanner != "trivy" {
		t.Errorf("expected scanner=trivy, got %s", f.Scanner)
	}
	if f.Remediation != "Upgrade to 0.17.0" {
		t.Errorf("unexpected remediation: %s", f.Remediation)
	}
	if f.ID == "" {
		t.Error("finding ID must not be empty")
	}
}

func TestParseTrivyJSON_Empty(t *testing.T) {
	findings, err := ParseTrivyJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTrivyJSON_CriticalSeverity(t *testing.T) {
	data := []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","InstalledVersion":"1.0.0","Severity":"CRITICAL","Title":"Critical OpenSSL Bug"}]}]}`)
	findings, err := ParseTrivyJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.SevCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

// ── rkhunter ──────────────────────────────────────────────────────────────────

const rkhunterSample = `
Checking for rootkits...

  Checking for '55808 Trojan - Variant A'    [ Not found ]
  Checking for Adore Worm                    [ Warning ]
  Checking network interfaces...
  Checking for suspicious network interfaces [ Warning ]
  Checking for loaded kernel modules...
  Checking for hidden kernel modules         [ Infected ]
`

func TestParseRkhunterOutput_WarningAndInfected(t *testing.T) {
	findings, err := ParseRkhunterOutput([]byte(rkhunterSample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	// Verify we have at least one HIGH (Warning) and one CRITICAL (Infected)
	var hasHigh, hasCritical bool
	for _, f := range findings {
		if f.Severity == scanner.SevHigh {
			hasHigh = true
		}
		if f.Severity == scanner.SevCritical {
			hasCritical = true
		}
		if f.Scanner != "rkhunter" {
			t.Errorf("expected scanner=rkhunter, got %s", f.Scanner)
		}
	}
	if !hasHigh {
		t.Error("expected at least one HIGH finding from Warning lines")
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL finding from Infected lines")
	}
}

func TestParseRkhunterOutput_Empty(t *testing.T) {
	findings, err := ParseRkhunterOutput(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseRkhunterOutput_NoFindings(t *testing.T) {
	data := []byte("Checking for rootkits...\n  All checks passed [ OK ]\n")
	findings, err := ParseRkhunterOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean output, got %d", len(findings))
	}
}

// ── SSH-audit ─────────────────────────────────────────────────────────────────

const sshAuditSample = `{
  "banner": {
    "raw": "SSH-2.0-OpenSSH_7.4"
  },
  "recommendations": [
    {
      "key": "diffie-hellman-group14-sha1",
      "value": "Remove this key exchange algorithm (weak SHA-1 hash)",
      "severity": "warn"
    },
    {
      "key": "hmac-md5",
      "value": "Remove this MAC algorithm (broken MD5 hash)",
      "severity": "fail"
    }
  ]
}`

func TestParseSSHAuditJSON_Recommendations(t *testing.T) {
	findings, err := ParseSSHAuditJSON([]byte(sshAuditSample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	var hasHigh, hasMedium bool
	for _, f := range findings {
		if f.Scanner != "ssh-audit" {
			t.Errorf("expected scanner=ssh-audit, got %s", f.Scanner)
		}
		if f.Location != "SSH-2.0-OpenSSH_7.4" {
			t.Errorf("unexpected location: %s", f.Location)
		}
		if f.ID == "" {
			t.Error("finding ID must not be empty")
		}
		if f.Severity == scanner.SevHigh {
			hasHigh = true
		}
		if f.Severity == scanner.SevMedium {
			hasMedium = true
		}
	}
	if !hasHigh {
		t.Error("expected a HIGH finding for severity=fail")
	}
	if !hasMedium {
		t.Error("expected a MEDIUM finding for severity=warn")
	}
}

func TestParseSSHAuditJSON_Empty(t *testing.T) {
	findings, err := ParseSSHAuditJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// ── Additional edge-case tests ────────────────────────────────────────────────

func TestParseGitleaksJSON_MalformedJSON(t *testing.T) {
	// Invalid JSON (not an array) should return an error.
	_, err := ParseGitleaksJSON([]byte(`{"not": "an array"}`))
	if err == nil {
		t.Error("expected error for JSON object instead of array, got nil")
	}
}

func TestParseTrivyJSON_EmptyResults(t *testing.T) {
	// Results array present but empty — no vulnerabilities to parse.
	data := []byte(`{"Results": []}`)
	findings, err := ParseTrivyJSON(data)
	if err != nil {
		t.Fatalf("unexpected error for empty Results: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty Results array, got %d", len(findings))
	}
}

func TestParseTrivyJSON_MalformedJSON(t *testing.T) {
	_, err := ParseTrivyJSON([]byte(`{not valid json`))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestParseRkhunterOutput_NoWarnings(t *testing.T) {
	// Output that has no Warning or Infected lines — should produce 0 findings.
	cleanOutput := `Starting system checks:
  Checking for 55808 Trojan - Variant A               [ Not found ]
  Checking for ADM Worm                               [ Not found ]
  Checking for Apache Worm                            [ Not found ]
System checks summary
=====================
File properties checks...
All results have been written to the log file: /var/log/rkhunter.log`
	findings, err := ParseRkhunterOutput([]byte(cleanOutput))
	if err != nil {
		t.Fatalf("unexpected error for clean rkhunter output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean rkhunter output, got %d: %+v", len(findings), findings)
	}
}

func TestParseSSHAuditJSON_NoRecommendations(t *testing.T) {
	// Recommendations array is empty — should produce 0 findings.
	data := []byte(`{
		"banner": {"raw": "SSH-2.0-OpenSSH_8.9"},
		"recommendations": []
	}`)
	findings, err := ParseSSHAuditJSON(data)
	if err != nil {
		t.Fatalf("unexpected error for empty recommendations: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty recommendations, got %d", len(findings))
	}
}

func TestParseClamAVOutput_EmptyInput(t *testing.T) {
	// Empty input should return 0 findings, no error.
	findings, err := ParseClamAVOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty ClamAV output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(findings))
	}
}

func TestParseClamAVOutput_NoFOUND(t *testing.T) {
	// Lines that don't contain FOUND should produce 0 findings.
	output := `/var/lib/clamav/main.cvd: OK
/var/lib/clamav/daily.cvd: OK
----------- SCAN SUMMARY -----------
Known viruses: 8662500
Engine version: 0.103.8
Scanned directories: 1
Scanned files: 2
Infected files: 0
Data scanned: 2.50 MB
Time: 5.200 sec (0 m 5 s)`
	findings, err := ParseClamAVOutput([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error for clean ClamAV output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ClamAV output without FOUND lines, got %d", len(findings))
	}
}

func TestParseClamAVOutput_WithFOUND(t *testing.T) {
	// Ensure FOUND lines are parsed correctly.
	output := `/tmp/eicar.com: Eicar-Signature FOUND
/tmp/clean.txt: OK`
	findings, err := ParseClamAVOutput([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for FOUND line, got %d", len(findings))
	}
	if findings[0].Scanner != "rootkit" {
		t.Errorf("expected scanner=rootkit, got %q", findings[0].Scanner)
	}
	if findings[0].Location != "/tmp/eicar.com" {
		t.Errorf("unexpected location: %q", findings[0].Location)
	}
}

func TestParseTrivyJSON_MediumAndLowSeverity(t *testing.T) {
	data := []byte(`{"Results":[{"Vulnerabilities":[
		{"VulnerabilityID":"CVE-2024-0002","PkgName":"libfoo","InstalledVersion":"1.0","Severity":"MEDIUM","Title":"Medium Bug"},
		{"VulnerabilityID":"CVE-2024-0003","PkgName":"libbar","InstalledVersion":"2.0","Severity":"LOW","Title":"Low Bug"},
		{"VulnerabilityID":"CVE-2024-0004","PkgName":"libbaz","InstalledVersion":"3.0","Severity":"INFO","Title":"Info Bug"}
	]}]}`)
	findings, err := ParseTrivyJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	sevByTitle := make(map[string]int)
	for _, f := range findings {
		sevByTitle[f.Title] = int(f.Severity)
	}
	if sevByTitle["Medium Bug"] != 1 {
		t.Errorf("expected MEDIUM=1 for 'Medium Bug', got %d", sevByTitle["Medium Bug"])
	}
	if sevByTitle["Low Bug"] != 0 {
		t.Errorf("expected LOW=0 for 'Low Bug', got %d", sevByTitle["Low Bug"])
	}
	if sevByTitle["Info Bug"] != 0 {
		t.Errorf("expected LOW=0 for unknown severity 'INFO', got %d", sevByTitle["Info Bug"])
	}
}

func TestParseSSHAuditJSON_SeverityLow(t *testing.T) {
	// "info" severity should map to LOW.
	data := []byte(`{
		"banner": {"raw": "SSH-2.0-OpenSSH_8.9"},
		"recommendations": [
			{"key": "some-algo", "value": "informational note", "severity": "info"}
		]
	}`)
	findings, err := ParseSSHAuditJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != 0 { // SevLow = 0
		t.Errorf("expected LOW severity for 'info', got %d", findings[0].Severity)
	}
}

// ── truncate helper ───────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	cases := []struct {
		input    string
		max      int
		wantLen  int
		wantSame bool
	}{
		{"hello", 10, 5, true},
		{"hello world", 5, 6, false}, // 5 runes + "…"
		{"", 10, 0, true},
	}
	for _, c := range cases {
		got := truncate(c.input, c.max)
		if c.wantSame && got != c.input {
			t.Errorf("truncate(%q, %d) = %q; want unchanged", c.input, c.max, got)
		}
		if !c.wantSame && len([]rune(got)) != c.wantLen {
			t.Errorf("truncate(%q, %d) rune len = %d; want %d", c.input, c.max, len([]rune(got)), c.wantLen)
		}
	}
}
