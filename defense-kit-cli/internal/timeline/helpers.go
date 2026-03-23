package timeline

import (
	"bufio"
	"io"
)

// newLineScanner returns a *bufio.Scanner that reads one line at a time.
// This is extracted to a helper so both production code and tests can share it.
func newLineScanner(r io.Reader) *bufio.Scanner {
	return bufio.NewScanner(r)
}
