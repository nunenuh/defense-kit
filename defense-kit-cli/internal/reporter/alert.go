package reporter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const evidenceMaxLen = 100

// Alerter is the interface that all alert delivery backends must implement.
type Alerter interface {
	// Name returns a human-readable identifier for this alerter.
	Name() string
	// Send delivers an AlertReport through this alerter's channel.
	Send(ctx context.Context, report AlertReport) error
}

// AlertReport is the payload delivered to each Alerter.
type AlertReport struct {
	Host     string            `json:"host"`
	ScanID   string            `json:"scan_id"`
	Time     time.Time         `json:"time"`
	Summary  SeveritySummary   `json:"summary"`
	Findings []scanner.Finding `json:"findings"`
}

// alerterEntry pairs an Alerter with its minimum severity threshold.
type alerterEntry struct {
	alerter     Alerter
	minSeverity scanner.Severity
}

// AlertDispatcher fans out scan results to one or more Alerter backends,
// filtering findings by severity and redacting long evidence strings.
type AlertDispatcher struct {
	alerters []alerterEntry
}

// NewAlertDispatcher returns a new, empty AlertDispatcher.
func NewAlertDispatcher() *AlertDispatcher {
	return &AlertDispatcher{}
}

// Add registers an Alerter that will receive findings with severity >= minSeverity.
func (d *AlertDispatcher) Add(a Alerter, minSeverity scanner.Severity) {
	d.alerters = append(d.alerters, alerterEntry{alerter: a, minSeverity: minSeverity})
}

// Dispatch collects all findings from results, then for each registered alerter
// builds a filtered, evidence-redacted AlertReport and calls Send.
// All alerter errors are collected and returned as a single combined error.
func (d *AlertDispatcher) Dispatch(ctx context.Context, results []scanner.ScanResult, host, scanID string) error {
	// Collect all findings.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	now := time.Now()

	var errs []string
	for _, entry := range d.alerters {
		filtered := filterAndRedact(allFindings, entry.minSeverity)

		counts := CountBySeverity(filtered)
		summary := SeveritySummary{
			Critical: counts[scanner.SevCritical],
			High:     counts[scanner.SevHigh],
			Medium:   counts[scanner.SevMedium],
			Low:      counts[scanner.SevLow],
			Total:    len(filtered),
		}

		report := AlertReport{
			Host:     host,
			ScanID:   scanID,
			Time:     now,
			Summary:  summary,
			Findings: filtered,
		}

		if err := entry.alerter.Send(ctx, report); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", entry.alerter.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("alert dispatch errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// filterAndRedact returns a new slice containing only findings with severity >=
// minSeverity, with evidence truncated to evidenceMaxLen characters.
func filterAndRedact(findings []scanner.Finding, minSeverity scanner.Severity) []scanner.Finding {
	result := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity < minSeverity {
			continue
		}
		// Immutable copy with redacted evidence.
		redacted := f
		if len(redacted.Evidence) > evidenceMaxLen {
			redacted.Evidence = redacted.Evidence[:evidenceMaxLen]
		}
		result = append(result, redacted)
	}
	return result
}
