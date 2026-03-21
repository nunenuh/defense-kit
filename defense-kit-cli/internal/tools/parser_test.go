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
