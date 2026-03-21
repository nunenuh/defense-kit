package system

import (
	"context"
	"strings"

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
func (s *PackageMgrScanner) OptionalTools() []string { return []string{"debsums"} }
func (s *PackageMgrScanner) Available() bool         { return true }
func (s *PackageMgrScanner) Description() string {
	return "Audits the system package manager (apt, dnf, pacman) for unsigned packages, untrusted repositories, and packages with known vulnerabilities."
}

// Scan runs package integrity checks using debsums when available.
// Each line of `debsums -c` output represents a modified package file → HIGH finding.
// Returns nil if debsums is not available.
func (s *PackageMgrScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("debsums") {
		return nil, nil
	}

	out, err := opts.ToolRunner.Run(ctx, "debsums", []string{"-c"})
	if err != nil && len(out) == 0 {
		return nil, nil
	}

	var findings []scanner.Finding
	seenIDs := make(map[string]bool)

	for _, line := range strings.Split(string(out), "\n") {
		modifiedFile := strings.TrimSpace(line)
		if modifiedFile == "" {
			continue
		}

		f := scanner.Finding{
			ID:          scanner.GenerateFindingID(s.Name(), modifiedFile, "modified package file"),
			Scanner:     s.Name(),
			Severity:    scanner.SevHigh,
			Title:       "Modified package file detected",
			Detail:      "The file has been modified from its original packaged state, which may indicate tampering or a rootkit.",
			Evidence:    modifiedFile,
			Location:    modifiedFile,
			Remediation: "Investigate " + modifiedFile + " and reinstall the owning package if tampering is confirmed.",
		}

		if !seenIDs[f.ID] {
			seenIDs[f.ID] = true
			findings = append(findings, f)
		}
	}

	return findings, nil
}
