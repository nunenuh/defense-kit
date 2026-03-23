package scanner

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// ProgressFunc is called just before each scanner starts.
// current is 1-based (the scanner about to run), total is the total count.
type ProgressFunc func(current, total int, scannerName string)

// RunWithProgress is identical to Run but calls progress before each scanner
// starts.  progress may be nil (no-op).
func (e *Engine) RunWithProgress(ctx context.Context, opts ScanOptions, progress ProgressFunc) []ScanResult {
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

	total := len(scanners)
	results := make([]ScanResult, total)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	// counter is atomically incremented so each goroutine gets a unique
	// 1-based index for the progress callback.
	var counter int64

	for i, s := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()

			// Acquire semaphore slot.
			sem <- struct{}{}
			defer func() { <-sem }()

			// Report progress before running.
			if progress != nil {
				current := int(atomic.AddInt64(&counter, 1))
				progress(current, total, sc.Name())
			}

			results[idx] = runOne(ctx, sc, opts, timeout)
		}(i, s)
	}

	wg.Wait()
	return results
}
