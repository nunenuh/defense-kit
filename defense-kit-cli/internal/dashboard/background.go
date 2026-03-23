package dashboard

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
)

// BackgroundScanner runs periodic scans and stores results + notifications in the DB.
type BackgroundScanner struct {
	db       *DB
	registry *scanner.Registry
	mu       sync.Mutex
	interval time.Duration
	stopCh   chan struct{}
	running  bool
}

// NewBackgroundScanner constructs a BackgroundScanner.
func NewBackgroundScanner(db *DB, registry *scanner.Registry, interval time.Duration) *BackgroundScanner {
	return &BackgroundScanner{
		db:       db,
		registry: registry,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start launches the background scan loop in a goroutine.
// It is a no-op if the scanner is already running.
func (b *BackgroundScanner) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return
	}

	// Replace stop channel so a previous Stop doesn't bleed over.
	b.stopCh = make(chan struct{})
	b.running = true

	go b.loop()
}

// Stop signals the background loop to exit and waits until it acknowledges.
func (b *BackgroundScanner) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	ch := b.stopCh
	b.mu.Unlock()

	close(ch)

	// Poll until loop marks running=false.
	for {
		b.mu.Lock()
		r := b.running
		b.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// IsRunning reports whether the background loop is active.
func (b *BackgroundScanner) IsRunning() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.running
}

// SetInterval updates the scan interval.
// The new value takes effect on the next tick.
func (b *BackgroundScanner) SetInterval(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.interval = d
}

// loop is the goroutine that drives periodic scanning.
func (b *BackgroundScanner) loop() {
	defer func() {
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()

	for {
		b.mu.Lock()
		interval := b.interval
		stopCh := b.stopCh
		b.mu.Unlock()

		ticker := time.NewTicker(interval)
		select {
		case <-stopCh:
			ticker.Stop()
			return
		case <-ticker.C:
			ticker.Stop()
			b.runOneScan(stopCh)
		}
	}
}

// runOneScan performs one quick scan, persists results, and fires notifications
// for new CRITICAL or HIGH findings.
func (b *BackgroundScanner) runOneScan(stopCh <-chan struct{}) {
	select {
	case <-stopCh:
		return
	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	eng := scanner.NewEngine(b.registry)
	opts := scanner.ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: 2,
		Quick:       true,
		ToolRunner:  tools.NewRunner(),
	}

	start := time.Now()
	results := eng.Run(ctx, opts)

	var allFindings []scanner.Finding
	for _, res := range results {
		allFindings = append(allFindings, res.Findings...)
	}

	host, _ := os.Hostname()
	scanID := fmt.Sprintf("bg-%s", time.Now().UTC().Format("20060102-150405.000000000"))
	rec := ScanRecord{
		ID:        scanID,
		Timestamp: time.Now().UTC(),
		Host:      host,
		Duration:  int(time.Since(start).Milliseconds()),
		Total:     len(allFindings),
		Status:    "completed",
	}
	for _, f := range allFindings {
		switch f.Severity {
		case scanner.SevCritical:
			rec.Critical++
		case scanner.SevHigh:
			rec.High++
		case scanner.SevMedium:
			rec.Medium++
		default:
			rec.Low++
		}
	}

	_ = b.db.SaveScan(rec)
	_ = b.db.SaveFindings(scanID, allFindings)

	// Notify for CRITICAL and HIGH findings.
	for _, f := range allFindings {
		if f.Severity == scanner.SevCritical || f.Severity == scanner.SevHigh {
			_ = b.db.AddNotification(Notification{
				Timestamp: time.Now().UTC(),
				Type:      "background_scan",
				Severity:  int(f.Severity),
				Title:     fmt.Sprintf("[%s] %s", f.Severity.String(), f.Title),
				Body:      fmt.Sprintf("Scanner: %s | Location: %s | %s", f.Scanner, f.Location, f.Detail),
			})
		}
	}
}
