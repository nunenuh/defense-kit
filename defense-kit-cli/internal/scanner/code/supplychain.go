package code

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// SupplyChainScanner checks for supply-chain security issues in code dependencies.
type SupplyChainScanner struct{}

// NewSupplyChainScanner creates a new SupplyChainScanner.
func NewSupplyChainScanner() *SupplyChainScanner {
	return &SupplyChainScanner{}
}

func (s *SupplyChainScanner) Name() string            { return "supply_chain" }
func (s *SupplyChainScanner) Category() string        { return "code" }
func (s *SupplyChainScanner) RequiresRoot() bool      { return false }
func (s *SupplyChainScanner) RequiredTools() []string { return nil }
func (s *SupplyChainScanner) OptionalTools() []string { return nil }
func (s *SupplyChainScanner) Available() bool         { return true }
func (s *SupplyChainScanner) Description() string {
	return "Checks for supply-chain security issues such as dependency confusion, typosquatting, and use of unpinned or vulnerable dependencies."
}

// Scan is a stub — not yet implemented.
func (s *SupplyChainScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
