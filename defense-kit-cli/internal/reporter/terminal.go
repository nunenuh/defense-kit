package reporter

import (
	"fmt"
	"io"
	"sort"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const (
	ansiReset    = "\033[0m"
	ansiCritical = "\033[1;31m" // bold red
	ansiHigh     = "\033[0;31m" // red
	ansiMedium   = "\033[0;33m" // yellow
	ansiLow      = "\033[0;36m" // cyan
)

// TerminalReporter renders scan results to an io.Writer using ANSI colors.
type TerminalReporter struct {
	w io.Writer
}

// NewTerminalReporter returns a TerminalReporter that writes to w.
func NewTerminalReporter(w io.Writer) *TerminalReporter {
	return &TerminalReporter{w: w}
}

// Render collects all findings from results, sorts by severity (critical first),
// prints each finding with ANSI color, then prints a summary and any
// failed/skipped scanners.
func (t *TerminalReporter) Render(results []scanner.ScanResult) {
	// Collect all findings across results.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	// Sort by severity descending (critical=3 first).
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Severity > allFindings[j].Severity
	})

	// Print each finding.
	for _, f := range allFindings {
		color := severityColor(f.Severity)
		fmt.Fprintf(t.w, "%s[%s]%s %s\n", color, f.Severity.String(), ansiReset, f.Title)
		fmt.Fprintf(t.w, "  Location: %s\n", f.Location)
		fmt.Fprintf(t.w, "  Detail: %s\n", f.Detail)
		fmt.Fprintf(t.w, "  Evidence: %s\n", f.Evidence)
		fmt.Fprintf(t.w, "  Recommended: %s\n", f.Remediation)
	}

	// Print summary.
	counts := CountBySeverity(allFindings)
	fmt.Fprintf(t.w, "\nSCAN COMPLETE: %d findings — %d critical, %d high, %d medium, %d low\n",
		len(allFindings),
		counts[scanner.SevCritical],
		counts[scanner.SevHigh],
		counts[scanner.SevMedium],
		counts[scanner.SevLow],
	)

	// Print failed/skipped scanners.
	for _, r := range results {
		if r.Status == scanner.ScanFailed || r.Status == scanner.ScanSkipped {
			fmt.Fprintf(t.w, "[%s] scanner %s: %s\n", r.Status.String(), r.Scanner, r.Error)
		}
	}
}

// CountBySeverity returns a map of severity level to the count of findings
// at that level.
func CountBySeverity(findings []scanner.Finding) map[scanner.Severity]int {
	if len(findings) == 0 {
		return map[scanner.Severity]int{}
	}
	counts := make(map[scanner.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// severityColor returns the ANSI escape code for a given severity.
func severityColor(sev scanner.Severity) string {
	switch sev {
	case scanner.SevCritical:
		return ansiCritical
	case scanner.SevHigh:
		return ansiHigh
	case scanner.SevMedium:
		return ansiMedium
	default:
		return ansiLow
	}
}
