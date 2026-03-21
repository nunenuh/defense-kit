package persistence

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// ScanCronFileForTest exposes the internal scanCronFile function for use in
// external test packages. This file is only compiled during testing.
func ScanCronFileForTest(path string) ([]scanner.Finding, error) {
	return scanCronFile(path)
}
