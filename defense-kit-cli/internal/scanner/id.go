package scanner

import (
	"crypto/sha256"
	"fmt"
)

// GenerateFindingID produces a stable, unique identifier for a finding.
// Format: {scannerName}-{sha256(location+title)[:12]}
func GenerateFindingID(scannerName, location, title string) string {
	sum := sha256.Sum256([]byte(location + title))
	return fmt.Sprintf("%s-%x", scannerName, sum[:6])
}
