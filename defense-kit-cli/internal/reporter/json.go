package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// SeveritySummary holds counts of findings per severity level plus a total.
type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// ScanReport is the top-level JSON structure written by JSONReporter.
type ScanReport struct {
	ScanID   string               `json:"scan_id"`
	Host     string               `json:"host"`
	Time     time.Time            `json:"time"`
	Duration string               `json:"duration,omitempty"`
	Summary  SeveritySummary      `json:"summary"`
	Findings []scanner.Finding    `json:"findings"`
	Results  []scanner.ScanResult `json:"results"`
}

// JSONReporter writes scan results to a JSON file under a structured directory.
type JSONReporter struct {
	outputDir string
}

// NewJSONReporter returns a JSONReporter that will write reports under outputDir.
func NewJSONReporter(outputDir string) *JSONReporter {
	return &JSONReporter{outputDir: outputDir}
}

// Write aggregates findings from results, builds a ScanReport, writes it to
// {outputDir}/{scanID}/findings.json, and returns the scanID.
func (j *JSONReporter) Write(results []scanner.ScanResult, host string) (string, error) {
	now := time.Now()
	scanID := fmt.Sprintf("dk-%s", now.Format("20060102-150405"))

	// Collect all findings.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	// Build severity summary.
	counts := CountBySeverity(allFindings)
	summary := SeveritySummary{
		Critical: counts[scanner.SevCritical],
		High:     counts[scanner.SevHigh],
		Medium:   counts[scanner.SevMedium],
		Low:      counts[scanner.SevLow],
		Total:    len(allFindings),
	}

	report := ScanReport{
		ScanID:   scanID,
		Host:     host,
		Time:     now,
		Summary:  summary,
		Findings: allFindings,
		Results:  results,
	}

	// Create the directory.
	dir := filepath.Join(j.outputDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("reporter: create output directory: %w", err)
	}

	// Marshal and write.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("reporter: marshal report: %w", err)
	}

	outPath := j.OutputPath(scanID)
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("reporter: write findings.json: %w", err)
	}

	return scanID, nil
}

// OutputPath returns the full path to the findings.json file for a given scanID.
func (j *JSONReporter) OutputPath(scanID string) string {
	return filepath.Join(j.outputDir, scanID, "findings.json")
}
