package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the full defense-kit configuration.
type Config struct {
	Scan    ScanConfig    `yaml:"scan"`
	Tools   ToolsConfig   `yaml:"tools"`
	Alerts  AlertsConfig  `yaml:"alerts"`
	Monitor MonitorConfig `yaml:"monitor"`
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
