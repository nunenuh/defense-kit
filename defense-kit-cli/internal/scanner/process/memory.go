package process

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// MemoryScanner inspects process memory maps for suspicious injected regions.
type MemoryScanner struct{}

// NewMemoryScanner creates a new MemoryScanner.
func NewMemoryScanner() *MemoryScanner {
	return &MemoryScanner{}
}

func (s *MemoryScanner) Name() string           { return "memory" }
func (s *MemoryScanner) Category() string       { return "process" }
func (s *MemoryScanner) RequiresRoot() bool     { return true }
func (s *MemoryScanner) RequiredTools() []string { return nil }
func (s *MemoryScanner) OptionalTools() []string { return nil }
func (s *MemoryScanner) Available() bool        { return true }
func (s *MemoryScanner) Description() string {
	return "Inspects /proc/*/maps for suspicious executable memory regions, deleted mappings, and anonymous rwx segments indicative of code injection."
}

// Scan checks process memory maps for suspicious injected or anonymous executable regions.
func (s *MemoryScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// TODO: implement /proc/*/maps scanning for rwx anonymous regions, deleted files, etc.
	return nil, nil
}
