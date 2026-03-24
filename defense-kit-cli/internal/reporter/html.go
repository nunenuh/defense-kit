package reporter

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

//go:embed templates/report.html
var embeddedReportTemplate string

// scannerStatus holds the display data for a single scanner row in the report.
type scannerStatus struct {
	Name     string
	Status   string
	Duration string
}

// reportData is the data model passed to the HTML template.
type reportData struct {
	Host     string
	Time     string
	ScanID   string
	Summary  reportSummary
	Findings []findingRow
	Scanners []scannerStatus
}

// reportSummary holds per-severity counts plus a total.
type reportSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
}

// findingRow is a template-friendly view of scanner.Finding whose Severity
// is expressed as a string so the template can use it as a CSS class name.
type findingRow struct {
	Severity    string
	Title       string
	Scanner     string
	Location    string
	Evidence    string
	Remediation string
}

// HTMLReporter generates a self-contained HTML security report.
type HTMLReporter struct {
	templatePath string
}

// NewHTMLReporter returns an HTMLReporter that reads its template from templatePath.
func NewHTMLReporter(templatePath string) *HTMLReporter {
	return &HTMLReporter{templatePath: templatePath}
}

// Generate collects all findings from results, sorts by severity (critical first),
// builds the template data, and writes the rendered HTML to outputPath.
func (h *HTMLReporter) Generate(results []scanner.ScanResult, host string, outputPath string) error {
	// Collect all findings.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	// Sort by severity descending (critical=3 first).
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Severity > allFindings[j].Severity
	})

	// Count by severity.
	counts := CountBySeverity(allFindings)
	summary := reportSummary{
		Critical: counts[scanner.SevCritical],
		High:     counts[scanner.SevHigh],
		Medium:   counts[scanner.SevMedium],
		Low:      counts[scanner.SevLow],
		Total:    len(allFindings),
	}

	// Build finding rows (severity as string for CSS class / badge).
	rows := make([]findingRow, 0, len(allFindings))
	for _, f := range allFindings {
		rows = append(rows, findingRow{
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Scanner:     f.Scanner,
			Location:    f.Location,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
		})
	}

	// Build scanner status rows.
	statuses := make([]scannerStatus, 0, len(results))
	for _, r := range results {
		dur := r.Duration.Round(time.Millisecond).String()
		if r.Duration == 0 {
			dur = "—"
		}
		statuses = append(statuses, scannerStatus{
			Name:     r.Scanner,
			Status:   r.Status.String(),
			Duration: dur,
		})
	}

	now := time.Now()
	scanID := fmt.Sprintf("dk-%s", now.Format("20060102-150405"))

	data := reportData{
		Host:     host,
		Time:     now.Format("2006-01-02 15:04:05 UTC"),
		ScanID:   scanID,
		Summary:  summary,
		Findings: rows,
		Scanners: statuses,
	}

	// Parse template — prefer embedded template; fall back to filesystem path when
	// a custom template is explicitly provided and differs from the default.
	var tmpl *template.Template
	if h.templatePath == "" {
		t, parseErr := template.New("report.html").Parse(embeddedReportTemplate)
		if parseErr != nil {
			return fmt.Errorf("html reporter: parse embedded template: %w", parseErr)
		}
		tmpl = t
	} else {
		t, parseErr := template.ParseFiles(h.templatePath)
		if parseErr != nil {
			return fmt.Errorf("html reporter: parse template %q: %w", h.templatePath, parseErr)
		}
		tmpl = t
	}

	// Create output file.
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("html reporter: create output file %q: %w", outputPath, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("html reporter: execute template: %w", err)
	}

	return nil
}
