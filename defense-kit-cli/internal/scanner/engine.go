package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

const (
	defaultConcurrency = 0           // resolved at runtime to runtime.NumCPU()
	defaultTimeout     = 60 * time.Second
)

// Engine orchestrates parallel execution of scanners from a Registry.
type Engine struct {
	registry *Registry
}

// NewEngine returns an Engine backed by the provided Registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// Run selects scanners according to opts, executes them in parallel with a
// semaphore-limited concurrency, and returns results in the same order as the
// selected scanner list.
func (e *Engine) Run(ctx context.Context, opts ScanOptions) []ScanResult {
	scanners := e.selectScanners(opts)
	if len(scanners) == 0 {
		return []ScanResult{}
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if concurrency < 1 {
		concurrency = 1
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// Pre-allocate results slice so each goroutine can write to its own index
	// without a mutex, giving us deterministic ordering for free.
	results := make([]ScanResult, len(scanners))

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, s := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()

			// Acquire semaphore slot.
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = runOne(ctx, sc, opts, timeout)
		}(i, s)
	}

	wg.Wait()
	return results
}

// runOne executes a single scanner with its own context deadline and recovers
// any panic, mapping both panics and timeouts to ScanFailed.
func runOne(ctx context.Context, sc Scanner, opts ScanOptions, timeout time.Duration) (result ScanResult) {
	result = ScanResult{
		Scanner: sc.Name(),
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	defer func() {
		result.Duration = time.Since(start)
		if r := recover(); r != nil {
			result.Status = ScanFailed
			result.Error = fmt.Sprintf("panic: %v", r)
			result.Findings = nil
		}
	}()

	findings, err := sc.Scan(scanCtx, opts)
	result.Duration = time.Since(start)

	switch {
	case err != nil && len(findings) > 0:
		result.Status = ScanPartial
		result.Findings = findings
		result.Error = err.Error()
	case err != nil:
		result.Status = ScanFailed
		result.Error = err.Error()
	default:
		result.Status = ScanSuccess
		result.Findings = findings
	}

	return result
}

// selectScanners returns the subset of registered scanners to run, based on
// the filter logic described in the task spec:
//
//   - Quick mode with QuickCategories → filter by QuickCategories (category OR name)
//   - Categories not empty            → filter by Categories (category OR name)
//   - Otherwise                       → return all registered scanners
func (e *Engine) selectScanners(opts ScanOptions) []Scanner {
	all := e.registry.All()

	if opts.Quick && len(opts.QuickCategories) > 0 {
		return filterByKeys(all, opts.QuickCategories)
	}

	if len(opts.Categories) > 0 {
		return filterByKeys(all, opts.Categories)
	}

	return all
}

// filterByKeys returns scanners whose Category() OR Name() matches any key in
// the provided keys slice.
func filterByKeys(scanners []Scanner, keys []string) []Scanner {
	keySet := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keySet[k] = struct{}{}
	}

	var out []Scanner
	for _, s := range scanners {
		_, matchCat := keySet[s.Category()]
		_, matchName := keySet[s.Name()]
		if matchCat || matchName {
			out = append(out, s)
		}
	}
	return out
}
