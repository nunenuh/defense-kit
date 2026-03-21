package scanner

import (
	"context"
	"testing"
	"time"
)

// panicScanner panics inside Scan() to test engine recovery.
type panicScanner struct {
	name     string
	category string
}

func (p *panicScanner) Name() string             { return p.name }
func (p *panicScanner) Category() string         { return p.category }
func (p *panicScanner) Description() string      { return "panic scanner: " + p.name }
func (p *panicScanner) RequiredTools() []string  { return nil }
func (p *panicScanner) OptionalTools() []string  { return nil }
func (p *panicScanner) RequiresRoot() bool       { return false }
func (p *panicScanner) Available() bool          { return true }
func (p *panicScanner) Scan(_ context.Context, _ ScanOptions) ([]Finding, error) {
	panic("intentional panic in panicScanner")
}

// slowScanner blocks until the context is cancelled.
type slowScanner struct {
	name     string
	category string
}

func (s *slowScanner) Name() string             { return s.name }
func (s *slowScanner) Category() string         { return s.category }
func (s *slowScanner) Description() string      { return "slow scanner: " + s.name }
func (s *slowScanner) RequiredTools() []string  { return nil }
func (s *slowScanner) OptionalTools() []string  { return nil }
func (s *slowScanner) RequiresRoot() bool       { return false }
func (s *slowScanner) Available() bool          { return true }
func (s *slowScanner) Scan(ctx context.Context, _ ScanOptions) ([]Finding, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEngineRunAll(t *testing.T) {
	reg := newRegistry(
		newMock("scanner-a", "cat-a", true),
		newMock("scanner-b", "cat-b", true),
		newMock("scanner-c", "cat-c", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	results := engine.Run(context.Background(), opts)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != ScanSuccess {
			t.Errorf("scanner %q: expected ScanSuccess, got %s", r.Scanner, r.Status)
		}
		if len(r.Findings) != 1 {
			t.Errorf("scanner %q: expected 1 finding, got %d", r.Scanner, len(r.Findings))
		}
	}
}

func TestEngineRunAll_DeterministicOrder(t *testing.T) {
	reg := newRegistry(
		newMock("first", "cat", true),
		newMock("second", "cat", true),
		newMock("third", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	results := engine.Run(context.Background(), opts)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	names := []string{"first", "second", "third"}
	for i, r := range results {
		if r.Scanner != names[i] {
			t.Errorf("position %d: expected %q, got %q", i, names[i], r.Scanner)
		}
	}
}

func TestEngineFilterByCategory(t *testing.T) {
	reg := newRegistry(
		newMock("secrets-a", "secrets", true),
		newMock("network-a", "network", true),
		newMock("secrets-b", "secrets", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Categories: []string{"secrets"},
		Timeout:    5 * time.Second,
	}

	results := engine.Run(context.Background(), opts)

	if len(results) != 2 {
		t.Fatalf("expected 2 results for category 'secrets', got %d", len(results))
	}
	for _, r := range results {
		if r.Status != ScanSuccess {
			t.Errorf("scanner %q: expected ScanSuccess, got %s", r.Scanner, r.Status)
		}
	}
}

func TestEngineFilterByCategory_MatchesName(t *testing.T) {
	// The filter should also match by name, not just category.
	reg := newRegistry(
		newMock("special-scanner", "misc", true),
		newMock("other-scanner", "misc", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Categories: []string{"special-scanner"},
		Timeout:    5 * time.Second,
	}

	results := engine.Run(context.Background(), opts)

	if len(results) != 1 {
		t.Fatalf("expected 1 result matched by name, got %d", len(results))
	}
	if results[0].Scanner != "special-scanner" {
		t.Errorf("expected scanner 'special-scanner', got %q", results[0].Scanner)
	}
}

func TestEngineRecoversPanic(t *testing.T) {
	reg := newRegistry(
		newMock("normal-a", "cat", true),
		&panicScanner{name: "panicky", category: "cat"},
		newMock("normal-b", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	results := engine.Run(context.Background(), opts)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Find each result by name for order-independent checking.
	byName := make(map[string]ScanResult)
	for _, r := range results {
		byName[r.Scanner] = r
	}

	if byName["panicky"].Status != ScanFailed {
		t.Errorf("panicky scanner: expected ScanFailed, got %s", byName["panicky"].Status)
	}
	if byName["panicky"].Error == "" {
		t.Error("panicky scanner: expected non-empty Error field")
	}
	if byName["normal-a"].Status != ScanSuccess {
		t.Errorf("normal-a: expected ScanSuccess, got %s", byName["normal-a"].Status)
	}
	if byName["normal-b"].Status != ScanSuccess {
		t.Errorf("normal-b: expected ScanSuccess, got %s", byName["normal-b"].Status)
	}
}

func TestEngineTimeout(t *testing.T) {
	reg := newRegistry(
		newMock("fast", "cat", true),
		&slowScanner{name: "slow", category: "cat"},
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Timeout: 100 * time.Millisecond,
	}

	start := time.Now()
	results := engine.Run(context.Background(), opts)
	elapsed := time.Since(start)

	// The run should complete shortly after the timeout.
	if elapsed > 3*time.Second {
		t.Errorf("Run took too long: %v (expected ~100ms)", elapsed)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	byName := make(map[string]ScanResult)
	for _, r := range results {
		byName[r.Scanner] = r
	}

	if byName["slow"].Status != ScanFailed {
		t.Errorf("slow scanner: expected ScanFailed, got %s", byName["slow"].Status)
	}
	if byName["fast"].Status != ScanSuccess {
		t.Errorf("fast scanner: expected ScanSuccess, got %s", byName["fast"].Status)
	}
}

func TestEngineQuickMode(t *testing.T) {
	reg := newRegistry(
		newMock("secrets-scanner", "secrets", true),
		newMock("network-scanner", "network", true),
		newMock("fs-scanner", "filesystem", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Quick:           true,
		QuickCategories: []string{"secrets"},
		Timeout:         5 * time.Second,
	}

	results := engine.Run(context.Background(), opts)

	if len(results) != 1 {
		t.Fatalf("quick mode: expected 1 result for QuickCategories=['secrets'], got %d", len(results))
	}
	if results[0].Scanner != "secrets-scanner" {
		t.Errorf("quick mode: expected 'secrets-scanner', got %q", results[0].Scanner)
	}
}

func TestEngineQuickMode_FallsBackToAllWhenNoQuickCategories(t *testing.T) {
	reg := newRegistry(
		newMock("s1", "cat", true),
		newMock("s2", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Quick:   true,
		Timeout: 5 * time.Second,
		// QuickCategories is empty
	}

	results := engine.Run(context.Background(), opts)

	// When Quick is true but QuickCategories is empty, falls through to "all".
	if len(results) != 2 {
		t.Fatalf("expected 2 results (all scanners), got %d", len(results))
	}
}

func TestEngineDefaultConcurrency(t *testing.T) {
	// Verify the engine runs successfully with the default concurrency (Concurrency=0).
	reg := newRegistry(
		newMock("s1", "cat", true),
		newMock("s2", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Timeout:     5 * time.Second,
		Concurrency: 0, // should default to runtime.NumCPU()
	}

	results := engine.Run(context.Background(), opts)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestEngineDefaultTimeout(t *testing.T) {
	// Verify the engine runs successfully when Timeout=0 (should default to 60s).
	reg := newRegistry(
		newMock("s1", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Timeout: 0, // should default to 60s
	}

	results := engine.Run(context.Background(), opts)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != ScanSuccess {
		t.Errorf("expected ScanSuccess, got %s", results[0].Status)
	}
}
