package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	cfg := config.Defaults()

	// Scan defaults
	if cfg.Scan.Concurrency != 4 {
		t.Errorf("expected Scan.Concurrency=4, got %d", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != "60s" {
		t.Errorf("expected Scan.Timeout=60s, got %s", cfg.Scan.Timeout)
	}
	if cfg.Scan.TimeoutHeavy != "300s" {
		t.Errorf("expected Scan.TimeoutHeavy=300s, got %s", cfg.Scan.TimeoutHeavy)
	}

	expectedExclude := []string{"/proc", "/sys", "/dev"}
	if len(cfg.Scan.ExcludePaths) != len(expectedExclude) {
		t.Errorf("expected %d ExcludePaths, got %d", len(expectedExclude), len(cfg.Scan.ExcludePaths))
	} else {
		for i, p := range expectedExclude {
			if cfg.Scan.ExcludePaths[i] != p {
				t.Errorf("expected ExcludePaths[%d]=%s, got %s", i, p, cfg.Scan.ExcludePaths[i])
			}
		}
	}

	// Tools defaults
	if !cfg.Tools.PreferExternal {
		t.Error("expected Tools.PreferExternal=true")
	}
	if cfg.Tools.PythonPath != "/usr/bin/python3" {
		t.Errorf("expected Tools.PythonPath=/usr/bin/python3, got %s", cfg.Tools.PythonPath)
	}

	// Monitor defaults
	if cfg.Monitor.Interval != "5m" {
		t.Errorf("expected Monitor.Interval=5m, got %s", cfg.Monitor.Interval)
	}

	expectedCategories := []string{"processes", "network", "file_integrity", "persistence", "ssh", "shell_rc"}
	if len(cfg.Monitor.QuickCategories) != len(expectedCategories) {
		t.Errorf("expected %d QuickCategories, got %d", len(expectedCategories), len(cfg.Monitor.QuickCategories))
	} else {
		for i, c := range expectedCategories {
			if cfg.Monitor.QuickCategories[i] != c {
				t.Errorf("expected QuickCategories[%d]=%s, got %s", i, c, cfg.Monitor.QuickCategories[i])
			}
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	yamlContent := `
scan:
  concurrency: 8
  timeout: "120s"
  timeout_heavy: "600s"
  exclude_paths:
    - "/tmp"
    - "/var"
  categories:
    - "network"
    - "processes"
tools:
  prefer_external: false
  python_path: "/usr/local/bin/python3"
  tool_paths:
    nmap: "/usr/bin/nmap"
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/test"
    min_severity: "high"
  email:
    to: "admin@example.com"
    smtp_host: "smtp.example.com"
    min_severity: "critical"
  webhook:
    url: "https://example.com/hook"
    min_severity: "medium"
    hmac_secret: "secret123"
    require_tls: true
monitor:
  interval: "10m"
  quick_categories:
    - "network"
    - "ssh"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	// Scan overrides
	if cfg.Scan.Concurrency != 8 {
		t.Errorf("expected Scan.Concurrency=8, got %d", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != "120s" {
		t.Errorf("expected Scan.Timeout=120s, got %s", cfg.Scan.Timeout)
	}
	if cfg.Scan.TimeoutHeavy != "600s" {
		t.Errorf("expected Scan.TimeoutHeavy=600s, got %s", cfg.Scan.TimeoutHeavy)
	}
	if len(cfg.Scan.ExcludePaths) != 2 || cfg.Scan.ExcludePaths[0] != "/tmp" {
		t.Errorf("unexpected ExcludePaths: %v", cfg.Scan.ExcludePaths)
	}
	if len(cfg.Scan.Categories) != 2 || cfg.Scan.Categories[0] != "network" {
		t.Errorf("unexpected Categories: %v", cfg.Scan.Categories)
	}

	// Tools overrides
	if cfg.Tools.PreferExternal {
		t.Error("expected Tools.PreferExternal=false")
	}
	if cfg.Tools.PythonPath != "/usr/local/bin/python3" {
		t.Errorf("expected Tools.PythonPath=/usr/local/bin/python3, got %s", cfg.Tools.PythonPath)
	}
	if cfg.Tools.ToolPaths["nmap"] != "/usr/bin/nmap" {
		t.Errorf("expected ToolPaths[nmap]=/usr/bin/nmap, got %s", cfg.Tools.ToolPaths["nmap"])
	}

	// Alerts overrides
	if cfg.Alerts.Slack.WebhookURL != "https://hooks.slack.com/test" {
		t.Errorf("unexpected Slack.WebhookURL: %s", cfg.Alerts.Slack.WebhookURL)
	}
	if cfg.Alerts.Slack.MinSeverity != "high" {
		t.Errorf("unexpected Slack.MinSeverity: %s", cfg.Alerts.Slack.MinSeverity)
	}
	if cfg.Alerts.Email.To != "admin@example.com" {
		t.Errorf("unexpected Email.To: %s", cfg.Alerts.Email.To)
	}
	if cfg.Alerts.Email.SMTPHost != "smtp.example.com" {
		t.Errorf("unexpected Email.SMTPHost: %s", cfg.Alerts.Email.SMTPHost)
	}
	if cfg.Alerts.Webhook.URL != "https://example.com/hook" {
		t.Errorf("unexpected Webhook.URL: %s", cfg.Alerts.Webhook.URL)
	}
	if cfg.Alerts.Webhook.HMACSecret != "secret123" {
		t.Errorf("unexpected Webhook.HMACSecret: %s", cfg.Alerts.Webhook.HMACSecret)
	}
	if !cfg.Alerts.Webhook.RequireTLS {
		t.Error("expected Webhook.RequireTLS=true")
	}

	// Monitor overrides
	if cfg.Monitor.Interval != "10m" {
		t.Errorf("expected Monitor.Interval=10m, got %s", cfg.Monitor.Interval)
	}
	if len(cfg.Monitor.QuickCategories) != 2 || cfg.Monitor.QuickCategories[1] != "ssh" {
		t.Errorf("unexpected QuickCategories: %v", cfg.Monitor.QuickCategories)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := config.Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load of missing file returned unexpected error: %v", err)
	}

	defaults := config.Defaults()

	if cfg.Scan.Concurrency != defaults.Scan.Concurrency {
		t.Errorf("expected default Scan.Concurrency=%d, got %d", defaults.Scan.Concurrency, cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != defaults.Scan.Timeout {
		t.Errorf("expected default Scan.Timeout=%s, got %s", defaults.Scan.Timeout, cfg.Scan.Timeout)
	}
	if cfg.Tools.PythonPath != defaults.Tools.PythonPath {
		t.Errorf("expected default Tools.PythonPath=%s, got %s", defaults.Tools.PythonPath, cfg.Tools.PythonPath)
	}
	if cfg.Monitor.Interval != defaults.Monitor.Interval {
		t.Errorf("expected default Monitor.Interval=%s, got %s", defaults.Monitor.Interval, cfg.Monitor.Interval)
	}
}

// ---------------------------------------------------------------------------
// TestLoadPartialYAML — only scan.concurrency set; all other fields are defaults
// ---------------------------------------------------------------------------

func TestLoadPartialYAML(t *testing.T) {
	yamlContent := `
scan:
  concurrency: 16
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "partial.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.Scan.Concurrency != 16 {
		t.Errorf("expected Scan.Concurrency=16, got %d", cfg.Scan.Concurrency)
	}

	defaults := config.Defaults()

	// All other scan fields should remain at defaults.
	if cfg.Scan.Timeout != defaults.Scan.Timeout {
		t.Errorf("expected default Scan.Timeout=%s, got %s", defaults.Scan.Timeout, cfg.Scan.Timeout)
	}
	if cfg.Scan.TimeoutHeavy != defaults.Scan.TimeoutHeavy {
		t.Errorf("expected default Scan.TimeoutHeavy=%s, got %s", defaults.Scan.TimeoutHeavy, cfg.Scan.TimeoutHeavy)
	}
	if len(cfg.Scan.ExcludePaths) != len(defaults.Scan.ExcludePaths) {
		t.Errorf("expected %d default ExcludePaths, got %d", len(defaults.Scan.ExcludePaths), len(cfg.Scan.ExcludePaths))
	}

	// Tools, Monitor defaults must be preserved.
	if cfg.Tools.PythonPath != defaults.Tools.PythonPath {
		t.Errorf("expected default Tools.PythonPath=%s, got %s", defaults.Tools.PythonPath, cfg.Tools.PythonPath)
	}
	if cfg.Monitor.Interval != defaults.Monitor.Interval {
		t.Errorf("expected default Monitor.Interval=%s, got %s", defaults.Monitor.Interval, cfg.Monitor.Interval)
	}
}

// ---------------------------------------------------------------------------
// TestLoadInvalidYAML — garbage content must return an error
// ---------------------------------------------------------------------------

func TestLoadInvalidYAML(t *testing.T) {
	garbage := `{{{not: valid: yaml: ::::`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(configPath, []byte(garbage), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := config.Load(configPath)
	if err == nil {
		t.Fatal("expected Load to return an error for invalid YAML, but got nil")
	}
}

// ---------------------------------------------------------------------------
// TestLoadEmptyFile — empty file should return defaults without error
// ---------------------------------------------------------------------------

func TestLoadEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.yaml")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load of empty file returned unexpected error: %v", err)
	}

	defaults := config.Defaults()

	if cfg.Scan.Concurrency != defaults.Scan.Concurrency {
		t.Errorf("empty file: expected default Scan.Concurrency=%d, got %d", defaults.Scan.Concurrency, cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != defaults.Scan.Timeout {
		t.Errorf("empty file: expected default Scan.Timeout=%s, got %s", defaults.Scan.Timeout, cfg.Scan.Timeout)
	}
	if cfg.Tools.PythonPath != defaults.Tools.PythonPath {
		t.Errorf("empty file: expected default Tools.PythonPath=%s, got %s", defaults.Tools.PythonPath, cfg.Tools.PythonPath)
	}
	if cfg.Monitor.Interval != defaults.Monitor.Interval {
		t.Errorf("empty file: expected default Monitor.Interval=%s, got %s", defaults.Monitor.Interval, cfg.Monitor.Interval)
	}
}

// ---------------------------------------------------------------------------
// TestLoadAllAlertFields — all alert sub-fields are populated
// ---------------------------------------------------------------------------

func TestLoadAllAlertFields(t *testing.T) {
	yamlContent := `
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/abc123"
    min_severity: "critical"
  email:
    to: "security@example.com"
    smtp_host: "mail.example.com"
    min_severity: "high"
  webhook:
    url: "https://siem.example.com/ingest"
    min_severity: "medium"
    hmac_secret: "s3cr3t"
    require_tls: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "alerts.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.Alerts.Slack.WebhookURL != "https://hooks.slack.com/services/abc123" {
		t.Errorf("unexpected Slack.WebhookURL: %s", cfg.Alerts.Slack.WebhookURL)
	}
	if cfg.Alerts.Slack.MinSeverity != "critical" {
		t.Errorf("unexpected Slack.MinSeverity: %s", cfg.Alerts.Slack.MinSeverity)
	}
	if cfg.Alerts.Email.To != "security@example.com" {
		t.Errorf("unexpected Email.To: %s", cfg.Alerts.Email.To)
	}
	if cfg.Alerts.Email.SMTPHost != "mail.example.com" {
		t.Errorf("unexpected Email.SMTPHost: %s", cfg.Alerts.Email.SMTPHost)
	}
	if cfg.Alerts.Email.MinSeverity != "high" {
		t.Errorf("unexpected Email.MinSeverity: %s", cfg.Alerts.Email.MinSeverity)
	}
	if cfg.Alerts.Webhook.URL != "https://siem.example.com/ingest" {
		t.Errorf("unexpected Webhook.URL: %s", cfg.Alerts.Webhook.URL)
	}
	if cfg.Alerts.Webhook.MinSeverity != "medium" {
		t.Errorf("unexpected Webhook.MinSeverity: %s", cfg.Alerts.Webhook.MinSeverity)
	}
	if cfg.Alerts.Webhook.HMACSecret != "s3cr3t" {
		t.Errorf("unexpected Webhook.HMACSecret: %s", cfg.Alerts.Webhook.HMACSecret)
	}
	if !cfg.Alerts.Webhook.RequireTLS {
		t.Error("expected Webhook.RequireTLS=true")
	}
}

// ---------------------------------------------------------------------------
// TestLoadMonitorConfig — monitor section is populated correctly
// ---------------------------------------------------------------------------

func TestLoadMonitorConfig(t *testing.T) {
	yamlContent := `
monitor:
  interval: "15m"
  quick_categories:
    - "network"
    - "processes"
    - "ssh"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "monitor.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.Monitor.Interval != "15m" {
		t.Errorf("expected Monitor.Interval=15m, got %s", cfg.Monitor.Interval)
	}
	if len(cfg.Monitor.QuickCategories) != 3 {
		t.Errorf("expected 3 QuickCategories, got %d", len(cfg.Monitor.QuickCategories))
	}
	if cfg.Monitor.QuickCategories[0] != "network" {
		t.Errorf("expected QuickCategories[0]=network, got %s", cfg.Monitor.QuickCategories[0])
	}
	if cfg.Monitor.QuickCategories[2] != "ssh" {
		t.Errorf("expected QuickCategories[2]=ssh, got %s", cfg.Monitor.QuickCategories[2])
	}
}

// ---------------------------------------------------------------------------
// TestDefaults_AllFieldsPopulated — every non-zero field in Defaults()
// ---------------------------------------------------------------------------

func TestDefaults_AllFieldsPopulated(t *testing.T) {
	cfg := config.Defaults()

	// Scan fields
	if cfg.Scan.Concurrency == 0 {
		t.Error("Scan.Concurrency should be non-zero")
	}
	if cfg.Scan.Timeout == "" {
		t.Error("Scan.Timeout should not be empty")
	}
	if cfg.Scan.TimeoutHeavy == "" {
		t.Error("Scan.TimeoutHeavy should not be empty")
	}
	if len(cfg.Scan.ExcludePaths) == 0 {
		t.Error("Scan.ExcludePaths should not be empty")
	}

	// Tools fields
	if cfg.Tools.PythonPath == "" {
		t.Error("Tools.PythonPath should not be empty")
	}
	if cfg.Tools.ToolPaths == nil {
		t.Error("Tools.ToolPaths should not be nil")
	}

	// Monitor fields
	if cfg.Monitor.Interval == "" {
		t.Error("Monitor.Interval should not be empty")
	}
	if len(cfg.Monitor.QuickCategories) == 0 {
		t.Error("Monitor.QuickCategories should not be empty")
	}

	// Profiles
	if len(cfg.Profiles) == 0 {
		t.Error("Profiles should not be empty")
	}
	for name, profile := range cfg.Profiles {
		if len(profile.Categories) == 0 {
			t.Errorf("profile %q has no categories", name)
		}
	}
}

// ---------------------------------------------------------------------------
// TestLoad_OverridesDefaults — file values replace defaults; unset fields keep defaults
// ---------------------------------------------------------------------------

func TestLoad_OverridesDefaults(t *testing.T) {
	yamlContent := `
scan:
  concurrency: 2
  timeout: "30s"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "override.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	// Overridden values
	if cfg.Scan.Concurrency != 2 {
		t.Errorf("expected Scan.Concurrency=2, got %d", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != "30s" {
		t.Errorf("expected Scan.Timeout=30s, got %s", cfg.Scan.Timeout)
	}

	defaults := config.Defaults()

	// Unset fields keep defaults
	if cfg.Scan.TimeoutHeavy != defaults.Scan.TimeoutHeavy {
		t.Errorf("expected default Scan.TimeoutHeavy=%s, got %s", defaults.Scan.TimeoutHeavy, cfg.Scan.TimeoutHeavy)
	}
	if cfg.Tools.PythonPath != defaults.Tools.PythonPath {
		t.Errorf("expected default Tools.PythonPath=%s, got %s", defaults.Tools.PythonPath, cfg.Tools.PythonPath)
	}
	if cfg.Monitor.Interval != defaults.Monitor.Interval {
		t.Errorf("expected default Monitor.Interval=%s, got %s", defaults.Monitor.Interval, cfg.Monitor.Interval)
	}
	if len(cfg.Scan.ExcludePaths) != len(defaults.Scan.ExcludePaths) {
		t.Errorf("expected default ExcludePaths len=%d, got %d", len(defaults.Scan.ExcludePaths), len(cfg.Scan.ExcludePaths))
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestValidate_ValidDefaults(t *testing.T) {
	cfg := config.Defaults()
	warnings := cfg.Validate()
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for defaults, got: %v", warnings)
	}
}

func TestValidate_ConcurrencyZero(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.Concurrency = 0
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for Concurrency=0")
	}
}

func TestValidate_ConcurrencyTooHigh(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.Concurrency = 65
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for Concurrency=65 (exceeds max 64)")
	}
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.Timeout = "notaduration"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for invalid Scan.Timeout")
	}
}

func TestValidate_InvalidTimeoutHeavy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.TimeoutHeavy = "notaduration"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for invalid Scan.TimeoutHeavy")
	}
}

func TestValidate_InvalidSlackSeverity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Slack.MinSeverity = "disaster"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for unrecognised Slack.MinSeverity")
	}
}

func TestValidate_InvalidEmailSeverity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Email.MinSeverity = "extreme"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for unrecognised Email.MinSeverity")
	}
}

func TestValidate_InvalidWebhookSeverity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Webhook.MinSeverity = "unknown"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for unrecognised Webhook.MinSeverity")
	}
}

func TestValidate_ValidSeverities(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Slack.MinSeverity = "critical"
	cfg.Alerts.Email.MinSeverity = "high"
	cfg.Alerts.Webhook.MinSeverity = "medium"
	warnings := cfg.Validate()
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for valid severities, got: %v", warnings)
	}
}

func TestValidate_WebhookURLMissingScheme(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Webhook.URL = "siem.example.com/ingest"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for Webhook.URL missing http/https scheme")
	}
}

func TestValidate_WebhookURLValid(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Webhook.URL = "https://siem.example.com/ingest"
	warnings := cfg.Validate()
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for valid Webhook.URL, got: %v", warnings)
	}
}

func TestValidate_SlackWebhookURLMissingScheme(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Slack.WebhookURL = "hooks.slack.com/services/abc"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for Slack.WebhookURL missing http/https scheme")
	}
}

func TestValidate_EmailToMissingAt(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Email.To = "notanemailaddress"
	warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Error("expected a warning for Email.To without '@'")
	}
}

func TestValidate_EmailToValid(t *testing.T) {
	cfg := config.Defaults()
	cfg.Alerts.Email.To = "admin@example.com"
	warnings := cfg.Validate()
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for valid Email.To, got: %v", warnings)
	}
}
