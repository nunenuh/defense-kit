package scanner

import (
	"context"
	"testing"
)

// mockScanner is a test double implementing the Scanner interface.
type mockScanner struct {
	name      string
	category  string
	available bool
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Category() string    { return m.category }
func (m *mockScanner) Description() string { return "mock scanner: " + m.name }
func (m *mockScanner) RequiredTools() []string { return nil }
func (m *mockScanner) OptionalTools() []string { return nil }
func (m *mockScanner) RequiresRoot() bool  { return false }
func (m *mockScanner) Available() bool     { return m.available }

func (m *mockScanner) Scan(_ context.Context, _ ScanOptions) ([]Finding, error) {
	id := GenerateFindingID(m.name, "/test/path", "test finding")
	return []Finding{
		{
			ID:       id,
			Scanner:  m.name,
			Severity: SevLow,
			Title:    "test finding",
			Location: "/test/path",
		},
	}, nil
}

// helpers

func newMock(name, category string, available bool) Scanner {
	return &mockScanner{name: name, category: category, available: available}
}

func newRegistry(scanners ...Scanner) *Registry {
	r := NewRegistry()
	for _, s := range scanners {
		r.Register(s)
	}
	return r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewRegistry_IsEmpty(t *testing.T) {
	r := NewRegistry()
	if got := r.All(); len(got) != 0 {
		t.Fatalf("expected empty registry, got %d scanners", len(got))
	}
}

func TestRegister_And_All(t *testing.T) {
	r := newRegistry(
		newMock("secrets", "secrets", true),
		newMock("network", "network", true),
	)

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(all))
	}
}

func TestAll_ReturnsCopy(t *testing.T) {
	r := newRegistry(newMock("s1", "cat", true))
	all := r.All()
	all[0] = newMock("mutated", "cat", true) // modify the returned slice
	if r.All()[0].Name() == "mutated" {
		t.Fatal("All() must return a copy; internal slice was mutated")
	}
}

func TestByCategory_MultipleInSameCategory(t *testing.T) {
	r := newRegistry(
		newMock("secrets-a", "secrets", true),
		newMock("secrets-b", "secrets", true),
		newMock("network-a", "network", true),
	)

	got := r.ByCategory("secrets")
	if len(got) != 2 {
		t.Fatalf("expected 2 scanners in 'secrets', got %d", len(got))
	}
}

func TestByCategory_DifferentCategories(t *testing.T) {
	r := newRegistry(
		newMock("s1", "secrets", true),
		newMock("n1", "network", true),
	)

	if len(r.ByCategory("secrets")) != 1 {
		t.Fatal("expected 1 scanner in 'secrets'")
	}
	if len(r.ByCategory("network")) != 1 {
		t.Fatal("expected 1 scanner in 'network'")
	}
}

func TestByCategory_Nonexistent(t *testing.T) {
	r := newRegistry(newMock("s1", "secrets", true))
	got := r.ByCategory("nonexistent")
	if len(got) != 0 {
		t.Fatalf("expected 0 scanners for nonexistent category, got %d", len(got))
	}
}

func TestByName_Found(t *testing.T) {
	r := newRegistry(newMock("my-scanner", "cat", true))

	s, ok := r.ByName("my-scanner")
	if !ok {
		t.Fatal("expected to find 'my-scanner'")
	}
	if s.Name() != "my-scanner" {
		t.Fatalf("unexpected name: %s", s.Name())
	}
}

func TestByName_NotFound(t *testing.T) {
	r := newRegistry(newMock("s1", "cat", true))
	_, ok := r.ByName("does-not-exist")
	if ok {
		t.Fatal("expected ByName to return false for unknown scanner")
	}
}

func TestAvailable_FiltersUnavailable(t *testing.T) {
	r := newRegistry(
		newMock("available-1", "cat", true),
		newMock("unavailable-1", "cat", false),
		newMock("available-2", "cat", true),
	)

	avail := r.Available()
	if len(avail) != 2 {
		t.Fatalf("expected 2 available scanners, got %d", len(avail))
	}
	for _, s := range avail {
		if !s.Available() {
			t.Errorf("Available() returned unavailable scanner: %s", s.Name())
		}
	}
}

func TestCategories_UniqueList(t *testing.T) {
	r := newRegistry(
		newMock("s1", "secrets", true),
		newMock("s2", "secrets", true),
		newMock("n1", "network", true),
		newMock("f1", "filesystem", false),
	)

	cats := r.Categories()
	if len(cats) != 3 {
		t.Fatalf("expected 3 unique categories, got %d: %v", len(cats), cats)
	}

	seen := make(map[string]bool)
	for _, c := range cats {
		if seen[c] {
			t.Errorf("duplicate category returned: %s", c)
		}
		seen[c] = true
	}
}

func TestCategories_Empty(t *testing.T) {
	r := NewRegistry()
	if cats := r.Categories(); len(cats) != 0 {
		t.Fatalf("expected no categories for empty registry, got %v", cats)
	}
}

func TestMockScanner_Scan_ReturnsOneFinding(t *testing.T) {
	m := newMock("test-scanner", "cat", true)
	findings, err := m.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID == "" {
		t.Error("finding ID must not be empty")
	}
}
