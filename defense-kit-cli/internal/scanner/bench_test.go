package scanner

import (
	"context"
	"testing"
	"time"
)

// buildBenchRegistry builds a registry that approximates the full production
// scanner set using mock scanners. Using mocks here isolates the benchmark
// from the host environment (e.g. missing tools, slow I/O) so that the
// results measure only engine overhead — scheduling, synchronisation, and
// result aggregation — rather than individual scanner runtime.
//
// To benchmark real scanners end-to-end, build the binary and use the
// `defense-kit scan` command directly with `time(1)`.
func buildBenchRegistry(n int) *Registry {
	r := NewRegistry()
	categories := []string{
		"processes", "network", "persistence", "ssh", "shell_rc",
		"filesystem", "environment", "auth", "system", "code",
	}
	for i := 0; i < n; i++ {
		cat := categories[i%len(categories)]
		name := cat + "-mock-" + string(rune('a'+i%26))
		if i >= 26 {
			name = cat + "-mock-" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		}
		r.Register(newMock(name, cat, true))
	}
	return r
}

// BenchmarkEngineRunAll measures the engine scheduling overhead when running
// all registered scanners (approximated by 37 mocks matching the production
// registry size).
func BenchmarkEngineRunAll(b *testing.B) {
	reg := buildBenchRegistry(37)
	eng := NewEngine(reg)
	opts := ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: 4,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Run(context.Background(), opts)
	}
}

// BenchmarkEngineRunQuick measures the engine with quick-mode filtering active.
// Only scanners whose category matches one of the QuickCategories are selected,
// mimicking the `defense-kit scan --quick` code path.
func BenchmarkEngineRunQuick(b *testing.B) {
	reg := buildBenchRegistry(37)
	eng := NewEngine(reg)
	opts := ScanOptions{
		Quick:           true,
		QuickCategories: []string{"processes", "network", "persistence", "ssh", "shell_rc"},
		Timeout:         60 * time.Second,
		Concurrency:     4,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Run(context.Background(), opts)
	}
}

// BenchmarkEngineRunSingleScanner isolates the overhead of running a single
// scanner, giving a baseline for the per-scanner goroutine cost.
func BenchmarkEngineRunSingleScanner(b *testing.B) {
	reg := buildBenchRegistry(1)
	eng := NewEngine(reg)
	opts := ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: 1,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Run(context.Background(), opts)
	}
}

// BenchmarkEngineRunAllHighConcurrency measures engine throughput when
// concurrency matches the number of scanners, exercising maximum parallelism.
func BenchmarkEngineRunAllHighConcurrency(b *testing.B) {
	const numScanners = 37
	reg := buildBenchRegistry(numScanners)
	eng := NewEngine(reg)
	opts := ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: numScanners,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Run(context.Background(), opts)
	}
}
