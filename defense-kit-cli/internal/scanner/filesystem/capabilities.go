package filesystem

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// CapabilitiesScanner checks for binaries with elevated Linux capabilities
// that could be used for privilege escalation.
type CapabilitiesScanner struct{}

// NewCapabilitiesScanner creates a new CapabilitiesScanner.
func NewCapabilitiesScanner() *CapabilitiesScanner {
	return &CapabilitiesScanner{}
}

func (s *CapabilitiesScanner) Name() string           { return "capabilities" }
func (s *CapabilitiesScanner) Category() string       { return "filesystem" }
func (s *CapabilitiesScanner) RequiresRoot() bool     { return false }
func (s *CapabilitiesScanner) RequiredTools() []string { return nil }
func (s *CapabilitiesScanner) OptionalTools() []string { return nil }
func (s *CapabilitiesScanner) Available() bool        { return true }
func (s *CapabilitiesScanner) Description() string {
	return "Checks for binaries with elevated Linux capabilities (e.g., CAP_NET_RAW, CAP_SYS_PTRACE) that could be used for privilege escalation."
}

// Scan is a stub implementation that always returns nil findings.
func (s *CapabilitiesScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
