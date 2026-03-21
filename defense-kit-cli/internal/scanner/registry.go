package scanner

import "sync"

// Registry holds all registered scanners and provides lookup helpers.
type Registry struct {
	mu       sync.RWMutex
	scanners []Scanner
	byName   map[string]Scanner
}

// NewRegistry returns an initialised, empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[string]Scanner),
	}
}

// Register adds s to the registry.  If a scanner with the same name was
// already registered it is silently replaced.
func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byName[s.Name()]; !exists {
		r.scanners = append(r.scanners, s)
	} else {
		// Replace the existing entry in the slice.
		for i, existing := range r.scanners {
			if existing.Name() == s.Name() {
				r.scanners[i] = s
				break
			}
		}
	}
	r.byName[s.Name()] = s
}

// All returns a shallow copy of every registered scanner.
func (r *Registry) All() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Scanner, len(r.scanners))
	copy(out, r.scanners)
	return out
}

// ByCategory returns all scanners whose Category() equals cat.
func (r *Registry) ByCategory(cat string) []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Scanner
	for _, s := range r.scanners {
		if s.Category() == cat {
			out = append(out, s)
		}
	}
	return out
}

// ByName looks up a scanner by its name.  The second return value is false
// when no scanner with that name exists.
func (r *Registry) ByName(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, ok := r.byName[name]
	return s, ok
}

// Available returns all scanners for which Available() returns true.
func (r *Registry) Available() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Scanner
	for _, s := range r.scanners {
		if s.Available() {
			out = append(out, s)
		}
	}
	return out
}

// Categories returns a deduplicated, unordered list of all category names
// present in the registry.
func (r *Registry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{})
	var out []string
	for _, s := range r.scanners {
		cat := s.Category()
		if _, ok := seen[cat]; !ok {
			seen[cat] = struct{}{}
			out = append(out, cat)
		}
	}
	return out
}
