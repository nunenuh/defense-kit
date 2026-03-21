package filesystem

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// SwapScanner inspects swap space configuration for security issues such as
// unencrypted swap that may expose sensitive data at rest.
type SwapScanner struct{}

// NewSwapScanner creates a new SwapScanner.
func NewSwapScanner() *SwapScanner {
	return &SwapScanner{}
}

func (s *SwapScanner) Name() string           { return "swap" }
func (s *SwapScanner) Category() string       { return "filesystem" }
func (s *SwapScanner) RequiresRoot() bool     { return false }
func (s *SwapScanner) RequiredTools() []string { return nil }
func (s *SwapScanner) OptionalTools() []string { return nil }
func (s *SwapScanner) Available() bool        { return true }
func (s *SwapScanner) Description() string {
	return "Inspects swap space configuration for security issues such as unencrypted swap that may expose sensitive data at rest."
}

// Scan is a stub implementation that always returns nil findings.
func (s *SwapScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
