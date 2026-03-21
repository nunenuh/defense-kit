package network

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// FirewallScanner audits the host firewall configuration (iptables / nftables)
// for permissive rules or missing default-deny policies.
type FirewallScanner struct{}

// NewFirewallScanner creates a new FirewallScanner.
func NewFirewallScanner() *FirewallScanner {
	return &FirewallScanner{}
}

func (s *FirewallScanner) Name() string           { return "firewall" }
func (s *FirewallScanner) Category() string       { return "network" }
func (s *FirewallScanner) RequiresRoot() bool     { return true }
func (s *FirewallScanner) RequiredTools() []string { return nil }
func (s *FirewallScanner) OptionalTools() []string { return nil }
func (s *FirewallScanner) Available() bool        { return true }
func (s *FirewallScanner) Description() string {
	return "Audits host firewall configuration (iptables/nftables) for permissive rules or missing default-deny policies."
}

// Scan is a stub implementation that always returns nil findings.
func (s *FirewallScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
