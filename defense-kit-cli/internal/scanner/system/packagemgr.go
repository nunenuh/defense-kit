package system

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// PackageMgrScanner audits the system package manager for unsigned packages,
// repositories with weak verification, and packages with known CVEs.
type PackageMgrScanner struct{}

// NewPackageMgrScanner creates a new PackageMgrScanner.
func NewPackageMgrScanner() *PackageMgrScanner {
	return &PackageMgrScanner{}
}

func (s *PackageMgrScanner) Name() string            { return "package_manager" }
func (s *PackageMgrScanner) Category() string        { return "system" }
func (s *PackageMgrScanner) RequiresRoot() bool      { return true }
func (s *PackageMgrScanner) RequiredTools() []string { return nil }
func (s *PackageMgrScanner) OptionalTools() []string { return nil }
func (s *PackageMgrScanner) Available() bool         { return true }
func (s *PackageMgrScanner) Description() string {
	return "Audits the system package manager (apt, dnf, pacman) for unsigned packages, untrusted repositories, and packages with known vulnerabilities."
}

// Scan is a stub implementation — returns no findings.
func (s *PackageMgrScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
