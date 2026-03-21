package system

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// BootScanner audits bootloader configuration and secure boot settings.
type BootScanner struct{}

// NewBootScanner creates a new BootScanner.
func NewBootScanner() *BootScanner {
	return &BootScanner{}
}

func (s *BootScanner) Name() string            { return "boot" }
func (s *BootScanner) Category() string        { return "system" }
func (s *BootScanner) RequiresRoot() bool      { return true }
func (s *BootScanner) RequiredTools() []string { return nil }
func (s *BootScanner) OptionalTools() []string { return nil }
func (s *BootScanner) Available() bool         { return true }
func (s *BootScanner) Description() string {
	return "Audits bootloader configuration (GRUB, systemd-boot) and UEFI Secure Boot status for integrity weaknesses."
}

// Scan is a stub implementation — returns no findings.
func (s *BootScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
