package persistence

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ScheduledScanner checks for suspicious at(1) jobs and other scheduled tasks.
type ScheduledScanner struct{}

// NewScheduledScanner creates a new ScheduledScanner.
func NewScheduledScanner() *ScheduledScanner {
	return &ScheduledScanner{}
}

func (s *ScheduledScanner) Name() string           { return "scheduled" }
func (s *ScheduledScanner) Category() string       { return "persistence" }
func (s *ScheduledScanner) RequiresRoot() bool     { return true }
func (s *ScheduledScanner) RequiredTools() []string { return nil }
func (s *ScheduledScanner) OptionalTools() []string { return nil }
func (s *ScheduledScanner) Available() bool        { return true }
func (s *ScheduledScanner) Description() string {
	return "Scans at(1) job queues and other scheduled task mechanisms for suspicious persistence entries."
}

// Scan checks scheduled task queues (at jobs, etc.) for suspicious entries.
func (s *ScheduledScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// TODO: implement at(1) job and other scheduled task scanning
	return nil, nil
}
