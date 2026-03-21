package filesystem

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// TimestompScanner detects files whose timestamps have been manipulated to
// hide recent modifications (timestomping).
type TimestompScanner struct{}

// NewTimestompScanner creates a new TimestompScanner.
func NewTimestompScanner() *TimestompScanner {
	return &TimestompScanner{}
}

func (s *TimestompScanner) Name() string           { return "timestomp" }
func (s *TimestompScanner) Category() string       { return "filesystem" }
func (s *TimestompScanner) RequiresRoot() bool     { return false }
func (s *TimestompScanner) RequiredTools() []string { return nil }
func (s *TimestompScanner) OptionalTools() []string { return nil }
func (s *TimestompScanner) Available() bool        { return true }
func (s *TimestompScanner) Description() string {
	return "Detects files whose timestamps have been manipulated to hide recent modifications (timestomping)."
}

// Scan is a stub implementation that always returns nil findings.
func (s *TimestompScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
