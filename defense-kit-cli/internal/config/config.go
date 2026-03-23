package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// validSeverities is the set of recognised severity strings.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// Config holds the full defense-kit configuration.
type Config struct {
	Scan     ScanConfig               `yaml:"scan"`
	Tools    ToolsConfig              `yaml:"tools"`
	Alerts   AlertsConfig             `yaml:"alerts"`
	Monitor  MonitorConfig            `yaml:"monitor"`
	Profiles map[string]ProfileConfig `yaml:"profiles"`
}

// ProfileConfig defines a named scan profile with a set of categories.
type ProfileConfig struct {
	Categories []string `yaml:"categories"`
}

// ScanConfig controls scanning behaviour.
type ScanConfig struct {
	Concurrency  int      `yaml:"concurrency"`
	Timeout      string   `yaml:"timeout"`
	TimeoutHeavy string   `yaml:"timeout_heavy"`
	ExcludePaths []string `yaml:"exclude_paths"`
	Categories   []string `yaml:"categories"`
}

// ToolsConfig controls external tool integration.
type ToolsConfig struct {
	PreferExternal bool              `yaml:"prefer_external"`
	PythonPath     string            `yaml:"python_path"`
	ToolPaths      map[string]string `yaml:"tool_paths"`
}

// AlertsConfig groups all alerting channels.
type AlertsConfig struct {
	Slack   SlackConfig   `yaml:"slack"`
	Email   EmailConfig   `yaml:"email"`
	Webhook WebhookConfig `yaml:"webhook"`
}

// SlackConfig configures Slack alerts.
type SlackConfig struct {
	WebhookURL  string `yaml:"webhook_url"`
	MinSeverity string `yaml:"min_severity"`
}

// EmailConfig configures email alerts.
type EmailConfig struct {
	To          string `yaml:"to"`
	SMTPHost    string `yaml:"smtp_host"`
	MinSeverity string `yaml:"min_severity"`
}

// WebhookConfig configures generic webhook alerts.
type WebhookConfig struct {
	URL         string `yaml:"url"`
	MinSeverity string `yaml:"min_severity"`
	HMACSecret  string `yaml:"hmac_secret"`
	RequireTLS  bool   `yaml:"require_tls"`
}

// MonitorConfig controls continuous monitoring behaviour.
type MonitorConfig struct {
	Interval        string   `yaml:"interval"`
	QuickCategories []string `yaml:"quick_categories"`
}

// Defaults returns a Config populated with sensible default values.
func Defaults() Config {
	return Config{
		Scan: ScanConfig{
			Concurrency:  4,
			Timeout:      "60s",
			TimeoutHeavy: "300s",
			ExcludePaths: []string{"/proc", "/sys", "/dev"},
		},
		Tools: ToolsConfig{
			PreferExternal: true,
			PythonPath:     "/usr/bin/python3",
			ToolPaths:      map[string]string{},
		},
		Monitor: MonitorConfig{
			Interval: "5m",
			QuickCategories: []string{
				"processes",
				"network",
				"file_integrity",
				"persistence",
				"ssh",
				"shell_rc",
			},
		},
		Profiles: map[string]ProfileConfig{
			"workstation": {Categories: []string{"credentials", "ssh", "shell_rc", "env_vars", "processes", "cron", "browser", "git_hooks"}},
			"server":      {Categories: []string{"ssh", "firewall", "users", "rootkit", "logs", "network", "persistence", "sysctl", "auditd"}},
			"ci":          {Categories: []string{"credentials", "supply_chain", "containers", "git_hooks", "dependencies"}},
		},
	}
}

// Load reads a YAML config file from path and returns the resulting Config.
// If the file does not exist, Defaults() is returned without an error.
// Any other IO or parse error is returned to the caller.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Defaults(), nil
		}
		return Config{}, err
	}

	cfg := Defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration for common mistakes and returns a list of
// human-readable warning/error strings. An empty slice means the config is
// valid.
func (c Config) Validate() []string {
	var warnings []string

	// Scan.Concurrency
	if c.Scan.Concurrency <= 0 || c.Scan.Concurrency > 64 {
		warnings = append(warnings, fmt.Sprintf("scan.concurrency must be between 1 and 64 (got %d)", c.Scan.Concurrency))
	}

	// Scan.Timeout
	if c.Scan.Timeout != "" {
		if _, err := time.ParseDuration(c.Scan.Timeout); err != nil {
			warnings = append(warnings, fmt.Sprintf("scan.timeout is not a valid duration %q: %v", c.Scan.Timeout, err))
		}
	}

	// Scan.TimeoutHeavy
	if c.Scan.TimeoutHeavy != "" {
		if _, err := time.ParseDuration(c.Scan.TimeoutHeavy); err != nil {
			warnings = append(warnings, fmt.Sprintf("scan.timeout_heavy is not a valid duration %q: %v", c.Scan.TimeoutHeavy, err))
		}
	}

	// Severity fields
	severityFields := map[string]string{
		"alerts.slack.min_severity":   c.Alerts.Slack.MinSeverity,
		"alerts.email.min_severity":   c.Alerts.Email.MinSeverity,
		"alerts.webhook.min_severity": c.Alerts.Webhook.MinSeverity,
	}
	for field, val := range severityFields {
		if val != "" && !validSeverities[strings.ToLower(val)] {
			warnings = append(warnings, fmt.Sprintf("%s: unrecognised severity %q (valid: critical, high, medium, low)", field, val))
		}
	}

	// Webhook URL
	if c.Alerts.Webhook.URL != "" {
		if !strings.HasPrefix(c.Alerts.Webhook.URL, "http://") && !strings.HasPrefix(c.Alerts.Webhook.URL, "https://") {
			warnings = append(warnings, fmt.Sprintf("alerts.webhook.url must start with http:// or https:// (got %q)", c.Alerts.Webhook.URL))
		}
	}

	// Slack webhook URL
	if c.Alerts.Slack.WebhookURL != "" {
		if !strings.HasPrefix(c.Alerts.Slack.WebhookURL, "http://") && !strings.HasPrefix(c.Alerts.Slack.WebhookURL, "https://") {
			warnings = append(warnings, fmt.Sprintf("alerts.slack.webhook_url must start with http:// or https:// (got %q)", c.Alerts.Slack.WebhookURL))
		}
	}

	// Email address
	if c.Alerts.Email.To != "" && !strings.Contains(c.Alerts.Email.To, "@") {
		warnings = append(warnings, fmt.Sprintf("alerts.email.to does not look like an email address (missing @): %q", c.Alerts.Email.To))
	}

	return warnings
}
