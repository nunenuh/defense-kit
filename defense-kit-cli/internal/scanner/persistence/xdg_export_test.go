package persistence

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// NewXDGAutoStartScannerWithPaths exposes newXDGAutoStartScannerWithPaths for
// use in external test packages.
func NewXDGAutoStartScannerWithPaths(systemDir, homeBase string) *XDGAutoStartScanner {
	return newXDGAutoStartScannerWithPaths(systemDir, homeBase)
}

// ScanDesktopFileForTest exposes the internal scanDesktopFile method for use
// in external test packages.
func ScanDesktopFileForTest(s *XDGAutoStartScanner, path string, isRecent bool) []scanner.Finding {
	return s.scanDesktopFile(path, isRecent)
}
