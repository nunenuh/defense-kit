package persistence

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// ScanCronFileForTest exposes the internal scanCronFile function for use in
// external test packages. This file is only compiled during testing.
func ScanCronFileForTest(path string) ([]scanner.Finding, error) {
	return scanCronFile(path)
}

// ScanSystemServiceForTest exposes the internal scanSystemService function
// for use in external test packages. dpkgCheck controls whether dpkg ownership
// checks are included.
func ScanSystemServiceForTest(path string, dpkgCheck bool) []scanner.Finding {
	return scanSystemService(path, dpkgCheck)
}

// ScanDropInForTest exposes the internal scanDropIn function for use in
// external test packages.
func ScanDropInForTest(path string) []scanner.Finding {
	return scanDropIn(path)
}

// CheckExecLineForTest exposes the internal checkExecLine function for use in
// external test packages.
func CheckExecLineForTest(line, location string) []scanner.Finding {
	return checkExecLine(line, location, "systemd")
}
