package code

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ContainersScanner checks for security issues in container configurations.
type ContainersScanner struct{}

// NewContainersScanner creates a new ContainersScanner.
func NewContainersScanner() *ContainersScanner {
	return &ContainersScanner{}
}

func (s *ContainersScanner) Name() string            { return "containers" }
func (s *ContainersScanner) Category() string        { return "code" }
func (s *ContainersScanner) RequiresRoot() bool      { return false }
func (s *ContainersScanner) RequiredTools() []string { return nil }
func (s *ContainersScanner) OptionalTools() []string { return nil }
func (s *ContainersScanner) Available() bool         { return true }
func (s *ContainersScanner) Description() string {
	return "Checks for container security issues including privileged containers, exposed sockets, insecure base images, and missing security contexts."
}

// Scan is a stub — not yet implemented.
func (s *ContainersScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
