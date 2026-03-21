package persistence

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// SystemdScanner checks for suspicious systemd units, timers, and drop-ins.
type SystemdScanner struct{}

// NewSystemdScanner creates a new SystemdScanner.
func NewSystemdScanner() *SystemdScanner {
	return &SystemdScanner{}
}

func (s *SystemdScanner) Name() string           { return "systemd" }
func (s *SystemdScanner) Category() string       { return "persistence" }
func (s *SystemdScanner) RequiresRoot() bool     { return true }
func (s *SystemdScanner) RequiredTools() []string { return nil }
func (s *SystemdScanner) OptionalTools() []string { return nil }
func (s *SystemdScanner) Available() bool        { return true }
func (s *SystemdScanner) Description() string {
	return "Scans systemd unit files, timers, and drop-ins for suspicious persistence mechanisms."
}

// Scan checks systemd units, timers, and drop-ins for suspicious entries.
func (s *SystemdScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// TODO: implement systemd unit/timer/drop-in scanning
	return nil, nil
}
