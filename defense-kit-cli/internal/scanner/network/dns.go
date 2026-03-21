package network

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// DNSScanner checks DNS resolver configuration for signs of hijacking or
// misconfiguration (e.g., unexpected resolvers in /etc/resolv.conf).
type DNSScanner struct{}

// NewDNSScanner creates a new DNSScanner.
func NewDNSScanner() *DNSScanner {
	return &DNSScanner{}
}

func (s *DNSScanner) Name() string           { return "dns" }
func (s *DNSScanner) Category() string       { return "network" }
func (s *DNSScanner) RequiresRoot() bool     { return false }
func (s *DNSScanner) RequiredTools() []string { return nil }
func (s *DNSScanner) OptionalTools() []string { return nil }
func (s *DNSScanner) Available() bool        { return true }
func (s *DNSScanner) Description() string {
	return "Checks DNS resolver configuration for signs of hijacking or misconfiguration, including unexpected entries in /etc/resolv.conf and /etc/hosts."
}

// Scan is a stub implementation that always returns nil findings.
func (s *DNSScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
