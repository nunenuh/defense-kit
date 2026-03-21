package code

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
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
func (s *SupplyChainScanner) OptionalTools() []string { return []string{"trivy", "grype"} }
func (s *SupplyChainScanner) Available() bool         { return true }
func (s *SupplyChainScanner) Description() string {
	return "Checks for supply-chain security issues such as dependency confusion, typosquatting, and use of unpinned or vulnerable dependencies."
}

// Scan runs supply-chain security checks using trivy when available.
// No native fallback exists yet — returns nil if no tools are present.
func (s *SupplyChainScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("trivy") {
		return nil, nil
	}

	roots := opts.TargetPaths
	if len(roots) == 0 {
		return nil, nil
	}

	// Track findings by ID for deduplication.
	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	for _, root := range roots {
		out, err := opts.ToolRunner.Run(ctx, "trivy", []string{
			"fs", "--format", "json", "--quiet", root,
		})
		if err == nil || len(out) > 0 {
			trivyFindings, parseErr := tools.ParseTrivyJSON(out)
			if parseErr == nil {
				for _, f := range trivyFindings {
					if !seenIDs[f.ID] {
						seenIDs[f.ID] = true
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings, nil
}
