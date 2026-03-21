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
