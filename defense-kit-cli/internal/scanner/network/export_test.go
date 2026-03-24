package network

// ExtractListeningPortForTest exposes extractListeningPort for direct unit testing.
func ExtractListeningPortForTest(line string) (uint16, bool) {
	return extractListeningPort(line)
}

// ParseHexIPForTest exposes parseHexIP for direct unit testing.
func ParseHexIPForTest(hexStr string) string {
	return parseHexIP(hexStr)
}

// ParseHexPortForTest exposes parseHexPort for direct unit testing.
func ParseHexPortForTest(hexStr string) uint16 {
	return parseHexPort(hexStr)
}

// ExtractValueForTest exposes extractValue for direct unit testing.
func ExtractValueForTest(line string) string {
	return extractValue(line)
}
