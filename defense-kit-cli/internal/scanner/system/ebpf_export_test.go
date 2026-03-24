package system

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// ParseBPFToolOutputForTest exposes the unexported parseBPFToolOutput for unit tests.
func ParseBPFToolOutputForTest(data []byte) []scanner.Finding {
	return parseBPFToolOutput(data)
}

// NewEBPFScannerWithProcNetRaw creates an EBPFScanner with a custom
// /proc/net/raw path and the same path used as the procSysPath base — the
// tests pass a file path directly as procNetRawPath, and the sysctl checks are
// exercised separately.  For tests that want to exercise sysctl detection,
// use NewEBPFScannerWithPaths instead.
func NewEBPFScannerWithProcNetRaw(procNetRawPath string) *EBPFScanner {
	return newEBPFScannerWithPaths(procNetRawPath, "/nonexistent-proc-sys-test")
}

// NewEBPFScannerWithPaths creates an EBPFScanner with custom paths for both
// /proc/net/raw and the /proc/sys sysctl base directory.
func NewEBPFScannerWithPaths(procNetRawPath, procSysPath string) *EBPFScanner {
	return newEBPFScannerWithPaths(procNetRawPath, procSysPath)
}
