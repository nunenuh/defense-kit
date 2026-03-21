package monitor

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/baseline"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// Monitor performs a quick security scan and diffs the results against a
// stored baseline, writing a JSON report to outputDir on every run.
type Monitor struct {
	registry     *scanner.Registry
	baselinePath string
	outputDir    string
}

// MonitorResult is the outcome of a single Monitor.Run invocation.
type MonitorResult struct {
	// ScanResults is the raw output from the scanner engine.
	ScanResults []scanner.ScanResult
	// Diff contains the categorised differences against the previous baseline.
	// Empty when IsFirstRun is true.
	Diff baseline.DiffResult
	// IsFirstRun is true when no baseline existed before this run.
	IsFirstRun bool
	// BaselinePath is the path used to load/save the baseline.
	BaselinePath string
	// AllFindings is the flat list of every finding from this scan.
	AllFindings []scanner.Finding
}

// New returns a Monitor configured with the given registry, baseline file
// path, and output directory for JSON scan reports.
func New(registry *scanner.Registry, baselinePath, outputDir string) *Monitor {
	return &Monitor{
		registry:     registry,
		baselinePath: baselinePath,
		outputDir:    outputDir,
	}
}

// Run performs a quick scan (Quick is always forced to true), computes a diff
// against the stored baseline if one exists, and writes a JSON report to
// outputDir.  On the first run it saves the current findings as the new
// baseline and returns IsFirstRun=true.
func (m *Monitor) Run(ctx context.Context, opts scanner.ScanOptions) (MonitorResult, error) {
	// Always force quick mode.
	opts.Quick = true

	// Run the scan engine.
	engine := scanner.NewEngine(m.registry)
	scanResults := engine.Run(ctx, opts)

	// Collect all findings from every scan result.
	allFindings := collectFindings(scanResults)

	// Attempt to load an existing baseline.
	existing, err := baseline.Load(m.baselinePath)
	if err != nil {
		return MonitorResult{}, fmt.Errorf("monitor: load baseline: %w", err)
	}

	var (
		diff       baseline.DiffResult
		isFirstRun bool
	)

	if isEmptyBaseline(existing) {
		// First run: save the current findings as the baseline.
		isFirstRun = true

		newBaseline := baseline.Baseline{
			CreatedAt: time.Now().UTC(),
			Findings:  allFindings,
		}
		if saveErr := baseline.Save(m.baselinePath, newBaseline); saveErr != nil {
			return MonitorResult{}, fmt.Errorf("monitor: save baseline: %w", saveErr)
		}

		// Diff remains empty for the first run.
		diff = baseline.DiffResult{
			New:       []scanner.Finding{},
			Resolved:  []scanner.Finding{},
			Changed:   []baseline.FindingChange{},
			Unchanged: []scanner.Finding{},
		}
	} else {
		// Subsequent run: compute diff against the stored baseline.
		diff = baseline.Diff(existing, allFindings)
	}

	// Write JSON report to outputDir.
	if err := os.MkdirAll(m.outputDir, 0o755); err != nil {
		return MonitorResult{}, fmt.Errorf("monitor: create output dir: %w", err)
	}

	jsonReporter := reporter.NewJSONReporter(m.outputDir)
	if _, reportErr := jsonReporter.Write(scanResults, hostName()); reportErr != nil {
		return MonitorResult{}, fmt.Errorf("monitor: write report: %w", reportErr)
	}

	return MonitorResult{
		ScanResults:  scanResults,
		Diff:         diff,
		IsFirstRun:   isFirstRun,
		BaselinePath: m.baselinePath,
		AllFindings:  allFindings,
	}, nil
}

// collectFindings flattens findings from all ScanResults into a single slice.
func collectFindings(results []scanner.ScanResult) []scanner.Finding {
	var out []scanner.Finding
	for _, r := range results {
		out = append(out, r.Findings...)
	}
	if out == nil {
		out = []scanner.Finding{}
	}
	return out
}

// isEmptyBaseline returns true when the baseline carries no findings and has
// not been populated (version == 0 and empty findings list).
func isEmptyBaseline(b baseline.Baseline) bool {
	return b.Version == 0 && len(b.Findings) == 0
}

// hostName returns the system hostname, falling back to "unknown" on error.
func hostName() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
