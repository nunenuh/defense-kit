package scanner

import (
	"context"
	"sync"
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

func TestEngine_EmptyRegistry(t *testing.T) {
	// An engine backed by an empty registry should return an empty slice, not nil.
	reg := NewRegistry()
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	results := engine.Run(context.Background(), opts)

	if results == nil {
		t.Fatal("expected non-nil results slice for empty registry")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty registry, got %d", len(results))
	}
}

func TestEngine_AllScannersFiltered(t *testing.T) {
	// When the category filter matches nothing, the engine should return an empty slice.
	reg := newRegistry(
		newMock("scanner-a", "secrets", true),
		newMock("scanner-b", "network", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Categories: []string{"nonexistent-category"},
		Timeout:    5 * time.Second,
	}

	results := engine.Run(context.Background(), opts)

	if results == nil {
		t.Fatal("expected non-nil results slice when filter matches nothing")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results when all scanners are filtered out, got %d", len(results))
	}
}

func TestEngine_QuickModeWithEmptyQuickCategories(t *testing.T) {
	// When Quick=true but QuickCategories is empty, the engine should fall back to all scanners.
	reg := newRegistry(
		newMock("s1", "cat-a", true),
		newMock("s2", "cat-b", true),
		newMock("s3", "cat-c", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{
		Quick:           true,
		QuickCategories: []string{}, // empty — should fall back to all
		Timeout:         5 * time.Second,
	}

	results := engine.Run(context.Background(), opts)

	if len(results) != 3 {
		t.Fatalf("expected 3 results (all scanners) when Quick=true but QuickCategories empty, got %d", len(results))
	}
}

func TestRunWithProgress_CallsProgressFunc(t *testing.T) {
	reg := newRegistry(
		newMock("s1", "cat", true),
		newMock("s2", "cat", true),
		newMock("s3", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	var mu sync.Mutex
	var calls []string

	progress := func(current, total int, scannerName string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, scannerName)
	}

	results := engine.RunWithProgress(context.Background(), opts, progress)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 {
		t.Errorf("expected progress called 3 times, got %d", len(calls))
	}
}

func TestRunWithProgress_NilProgress(t *testing.T) {
	// Passing nil as the progress func should not panic.
	reg := newRegistry(
		newMock("s1", "cat", true),
		newMock("s2", "cat", true),
	)
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	results := engine.RunWithProgress(context.Background(), opts, nil)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != ScanSuccess {
			t.Errorf("scanner %q: expected ScanSuccess, got %s", r.Scanner, r.Status)
		}
	}
}

func TestRunWithProgress_EmptyRegistry(t *testing.T) {
	// An empty registry should return an empty slice without calling progress.
	reg := NewRegistry()
	engine := NewEngine(reg)
	opts := ScanOptions{Timeout: 5 * time.Second}

	called := false
	progress := func(_, _ int, _ string) { called = true }

	results := engine.RunWithProgress(context.Background(), opts, progress)

	if results == nil {
		t.Fatal("expected non-nil results slice")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty registry, got %d", len(results))
	}
	if called {
		t.Error("expected progress to not be called for empty registry")
	}
}
