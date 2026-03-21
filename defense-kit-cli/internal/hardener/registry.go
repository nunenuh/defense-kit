package hardener

import (
	"errors"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ErrNoHardener is returned by FindHardener when no registered hardener can
// handle the given finding.
var ErrNoHardener = errors.New("no hardener found for finding")

// HardenerRegistry keeps track of all registered Hardener implementations and
// provides lookup helpers.
type HardenerRegistry struct {
	hardeners []Hardener
}

// NewHardenerRegistry returns an initialised, empty HardenerRegistry.
func NewHardenerRegistry() *HardenerRegistry {
	return &HardenerRegistry{}
}

// Register adds h to the registry. Hardeners are stored in insertion order;
// the first registered hardener that reports CanFix wins.
func (r *HardenerRegistry) Register(h Hardener) {
	r.hardeners = append(r.hardeners, h)
}

// FindHardener returns the first registered Hardener that reports CanFix for f.
// If no such hardener exists, ErrNoHardener is returned.
func (r *HardenerRegistry) FindHardener(f scanner.Finding) (Hardener, error) {
	for _, h := range r.hardeners {
		if h.CanFix(f) {
			return h, nil
		}
	}
	return nil, ErrNoHardener
}

// FixableFindings filters findings to only those for which a registered
// hardener reports CanFix.
func (r *HardenerRegistry) FixableFindings(findings []scanner.Finding) []scanner.Finding {
	var out []scanner.Finding
	for _, f := range findings {
		if _, err := r.FindHardener(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}
