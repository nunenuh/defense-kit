package environment

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// CheckEtcEnvironmentForTest exposes checkEtcEnvironment for direct unit testing.
func CheckEtcEnvironmentForTest(path string) []scanner.Finding {
	return checkEtcEnvironment(path)
}

// CheckProfileDForTest exposes checkProfileD for direct unit testing.
func CheckProfileDForTest(dir string) []scanner.Finding {
	return checkProfileD(dir)
}

// ScanLDSoConfDForTest exposes scanLDSoConfD for direct unit testing.
func ScanLDSoConfDForTest(dir string) ([]scanner.Finding, error) {
	return scanLDSoConfD(dir)
}

// ScanLDConfFileForTest exposes scanLDConfFile for direct unit testing.
func ScanLDConfFileForTest(path string, prefixes []string) ([]scanner.Finding, error) {
	return scanLDConfFile(path, prefixes)
}
