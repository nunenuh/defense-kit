package network

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ConnectionsScanner inspects active network connections for suspicious
// outbound or lateral-movement traffic patterns.
type ConnectionsScanner struct{}

// NewConnectionsScanner creates a new ConnectionsScanner.
func NewConnectionsScanner() *ConnectionsScanner {
	return &ConnectionsScanner{}
}

func (s *ConnectionsScanner) Name() string           { return "connections" }
func (s *ConnectionsScanner) Category() string       { return "network" }
func (s *ConnectionsScanner) RequiresRoot() bool     { return false }
func (s *ConnectionsScanner) RequiredTools() []string { return nil }
func (s *ConnectionsScanner) OptionalTools() []string { return nil }
func (s *ConnectionsScanner) Available() bool        { return true }
func (s *ConnectionsScanner) Description() string {
	return "Inspects active network connections for suspicious outbound or lateral-movement traffic patterns."
}

// Scan is a stub implementation that always returns nil findings.
func (s *ConnectionsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
