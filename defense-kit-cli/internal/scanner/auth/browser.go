package auth

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// BrowserScanner checks browser credential stores and extension permissions
// for security issues.
type BrowserScanner struct{}

// NewBrowserScanner creates a new BrowserScanner.
func NewBrowserScanner() *BrowserScanner {
	return &BrowserScanner{}
}

func (s *BrowserScanner) Name() string            { return "browser" }
func (s *BrowserScanner) Category() string        { return "auth" }
func (s *BrowserScanner) RequiresRoot() bool      { return false }
func (s *BrowserScanner) RequiredTools() []string { return nil }
func (s *BrowserScanner) OptionalTools() []string { return nil }
func (s *BrowserScanner) Available() bool         { return true }
func (s *BrowserScanner) Description() string {
	return "Checks browser credential stores and extension permissions for stored plaintext credentials and overly-permissive extensions."
}

// Scan is a stub implementation — returns no findings.
func (s *BrowserScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
