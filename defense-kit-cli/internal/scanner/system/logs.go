package system

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// LogsScanner checks system log files for tampering, unexpected gaps, and
// suspicious entries that may indicate a compromise.
type LogsScanner struct{}

// NewLogsScanner creates a new LogsScanner.
func NewLogsScanner() *LogsScanner {
	return &LogsScanner{}
}

func (s *LogsScanner) Name() string            { return "logs" }
func (s *LogsScanner) Category() string        { return "system" }
func (s *LogsScanner) RequiresRoot() bool      { return false }
func (s *LogsScanner) RequiredTools() []string { return nil }
func (s *LogsScanner) OptionalTools() []string { return nil }
func (s *LogsScanner) Available() bool         { return true }
func (s *LogsScanner) Description() string {
	return "Checks system logs (/var/log) for tampering indicators, unexpected gaps, and suspicious authentication failure patterns."
}

// Scan is a stub implementation — returns no findings.
func (s *LogsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
