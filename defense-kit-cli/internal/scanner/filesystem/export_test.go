package filesystem

import "github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"

// SplitGetcapLineForTest exposes splitGetcapLine for direct unit testing.
func SplitGetcapLineForTest(line string) (binaryPath, caps string) {
	return splitGetcapLine(line)
}

// IsEncryptedSwapForTest exposes isEncryptedSwap for direct unit testing.
func IsEncryptedSwapForTest(device string) bool {
	return isEncryptedSwap(device)
}

// FindHiddenFilesForTest calls findHiddenFiles on a default AnomaliesScanner.
func FindHiddenFilesForTest(dir string) []scanner.Finding {
	s := &AnomaliesScanner{}
	return s.findHiddenFiles(dir)
}

// FindWorldWritableDirsForTest calls findWorldWritableDirs on a default AnomaliesScanner.
func FindWorldWritableDirsForTest(dir string) []scanner.Finding {
	s := &AnomaliesScanner{}
	return s.findWorldWritableDirs(dir)
}
