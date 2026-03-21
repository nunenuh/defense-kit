package network

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// VPNScanner checks for active VPN tunnel interfaces and validates their
// configuration for potential misrouting or split-tunnel issues.
type VPNScanner struct{}

// NewVPNScanner creates a new VPNScanner.
func NewVPNScanner() *VPNScanner {
	return &VPNScanner{}
}

func (s *VPNScanner) Name() string           { return "vpn" }
func (s *VPNScanner) Category() string       { return "network" }
func (s *VPNScanner) RequiresRoot() bool     { return false }
func (s *VPNScanner) RequiredTools() []string { return nil }
func (s *VPNScanner) OptionalTools() []string { return nil }
func (s *VPNScanner) Available() bool        { return true }
func (s *VPNScanner) Description() string {
	return "Checks for active VPN tunnel interfaces and validates their configuration for potential misrouting or split-tunnel issues."
}

// Scan is a stub implementation that always returns nil findings.
func (s *VPNScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
