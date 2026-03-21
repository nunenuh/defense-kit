package filesystem

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// AnomaliesScanner detects filesystem anomalies such as hidden files in
// unexpected locations, world-writable directories, and unusual file types.
type AnomaliesScanner struct{}

// NewAnomaliesScanner creates a new AnomaliesScanner.
func NewAnomaliesScanner() *AnomaliesScanner {
	return &AnomaliesScanner{}
}

func (s *AnomaliesScanner) Name() string           { return "filesystem" }
func (s *AnomaliesScanner) Category() string       { return "filesystem" }
func (s *AnomaliesScanner) RequiresRoot() bool     { return false }
func (s *AnomaliesScanner) RequiredTools() []string { return nil }
func (s *AnomaliesScanner) OptionalTools() []string { return nil }
func (s *AnomaliesScanner) Available() bool        { return true }
func (s *AnomaliesScanner) Description() string {
	return "Detects filesystem anomalies such as hidden files in unexpected locations, world-writable directories, and unusual file types."
}

// Scan is a stub implementation that always returns nil findings.
func (s *AnomaliesScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
