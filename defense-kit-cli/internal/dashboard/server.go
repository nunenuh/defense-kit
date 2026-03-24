package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
)

// Server is the HTTP server that powers the local security dashboard.
type Server struct {
	db        *DB
	registry  *scanner.Registry
	toolReg   *tools.ToolRegistry
	port      int
	mux       *http.ServeMux
	bgScanner *BackgroundScanner
	pages     map[string]*template.Template // page name → layout+page template
}

// pageData is the common data passed to every HTML template.
type pageData struct {
	Title          string
	Active         string
	Host           string
	LastScan       string
	Summary        severitySummary
	RecentFindings []findingRow
	Findings       []findingRow
	Scans          []ScanRecord
	Scanners       []scannerInfo
	ScannerNames   []string // plain scanner name list for findings filter dropdown
	Tools          []tools.ToolStatus
	TotalCount     int            // total item count for sub-pages
	AvailableCount int            // available scanner count for scanners page
	Config         DashboardConfig // settings page config
}

type severitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
}

type findingRow struct {
	ID            string
	Scanner       string
	Severity      int
	SeverityLabel string
	SeverityClass string
	Title         string
	Detail        string
	Evidence      string
	Location      string
	Remediation   string
	CanAutoFix    bool
}

type scannerInfo struct {
	Name        string
	Category    string
	Available   bool
	Description string
}

func severityLabel(sev int) string {
	switch scanner.Severity(sev) {
	case scanner.SevCritical:
		return "CRITICAL"
	case scanner.SevHigh:
		return "HIGH"
	case scanner.SevMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func severityClass(sev int) string {
	switch scanner.Severity(sev) {
	case scanner.SevCritical:
		return "critical"
	case scanner.SevHigh:
		return "high"
	case scanner.SevMedium:
		return "medium"
	default:
		return "low"
	}
}

func findingsToRows(findings []scanner.Finding) []findingRow {
	rows := make([]findingRow, len(findings))
	for i, f := range findings {
		rows[i] = findingRow{
			ID:            f.ID,
			Scanner:       f.Scanner,
			Severity:      int(f.Severity),
			SeverityLabel: severityLabel(int(f.Severity)),
			SeverityClass: severityClass(int(f.Severity)),
			Title:         f.Title,
			Detail:        f.Detail,
			Evidence:      f.Evidence,
			Location:      f.Location,
			Remediation:   f.Remediation,
			CanAutoFix:    f.CanAutoFix,
		}
	}
	return rows
}

// NewServer creates a Server wired to the given DB and scanner Registry.
func NewServer(db *DB, registry *scanner.Registry, port int) *Server {
	bg := NewBackgroundScanner(db, registry, 6*time.Hour)

	// Parse templates: each page = layout.html + page.html
	pageNames := []string{"home.html", "findings.html", "history.html", "scanners.html", "settings.html"}
	pages := make(map[string]*template.Template)
	for _, name := range pageNames {
		t, err := template.ParseFS(TemplateFS, "templates/layout.html", "templates/"+name)
		if err == nil {
			pages[name] = t
		}
	}

	s := &Server{
		db:        db,
		registry:  registry,
		toolReg:   tools.DefaultToolRegistry(),
		port:      port,
		mux:       http.NewServeMux(),
		bgScanner: bg,
		pages:     pages,
	}
	s.setupRoutes()
	return s
}

// Start begins listening on 127.0.0.1:{port}.
func (s *Server) Start() error {
	s.bgScanner.Start()
	defer s.bgScanner.Stop()
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	return http.ListenAndServe(addr, s.mux)
}

// StartWithContext begins listening and stops the background scanner when ctx is cancelled.
func (s *Server) StartWithContext(ctx context.Context) error {
	s.bgScanner.Start()
	go func() {
		<-ctx.Done()
		s.bgScanner.Stop()
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	return http.ListenAndServe(addr, s.mux)
}

// setupRoutes registers all HTTP routes on the internal ServeMux.
func (s *Server) setupRoutes() {
	// HTML pages.
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/findings", s.handleFindingsPage)
	s.mux.HandleFunc("/history", s.handleHistoryPage)
	s.mux.HandleFunc("/scanners", s.handleScannersPage)
	s.mux.HandleFunc("/settings", s.handleSettingsPage)

	// Static assets (embedded).
	staticFS, err := fs.Sub(StaticFS, "static")
	if err == nil {
		s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}

	// Core JSON API.
	s.mux.HandleFunc("/api/status", s.handleAPIStatus)
	s.mux.HandleFunc("/api/findings", s.handleAPIFindings)
	s.mux.HandleFunc("/api/history", s.handleAPIHistory)
	s.mux.HandleFunc("/api/trend", s.handleAPITrend)
	s.mux.HandleFunc("/api/scanners", s.handleAPIScanners)

	// Scan trigger + status polling.
	s.mux.HandleFunc("/api/scan", s.handleAPIScan)
	s.mux.HandleFunc("/api/scan/status/", s.handleAPIScanStatus)

	// Harden preview.
	s.mux.HandleFunc("/api/harden/preview", s.handleAPIHardenPreview)

	// Baseline.
	s.mux.HandleFunc("/api/baseline/update", s.handleAPIBaselineUpdate)
	s.mux.HandleFunc("/api/baseline/status", s.handleAPIBaselineStatus)

	// Schedule.
	s.mux.HandleFunc("/api/schedule/enable", s.handleAPIScheduleEnable)
	s.mux.HandleFunc("/api/schedule/disable", s.handleAPIScheduleDisable)
	s.mux.HandleFunc("/api/schedule/status", s.handleAPIScheduleStatus)

	// Notifications.
	s.mux.HandleFunc("/api/notifications", s.handleAPINotifications)
	s.mux.HandleFunc("/api/notifications/count", s.handleAPINotificationsCount)
	s.mux.HandleFunc("/api/notifications/read/", s.handleAPINotificationRead)

	// Settings.
	s.mux.HandleFunc("/api/settings", s.handleAPISettings)

	// Export.
	s.mux.HandleFunc("/api/export/", s.handleAPIExport)
}

// renderPage renders a page template within the layout.
// The page .html file must define {{define "content"}}...{{end}}.
// We execute layout.html which calls {{template "content" .}}.
// Output is buffered so that a template error returns a clean 500 instead of
// writing a partial 200 body and then calling WriteHeader again.
func (s *Server) renderPage(w http.ResponseWriter, page string, data pageData) {
	tmpl, ok := s.pages[page]
	if !ok || tmpl == nil {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// buildHomeData loads data for the home page.
func (s *Server) buildHomeData() pageData {
	host, _ := os.Hostname()

	data := pageData{
		Title:  "Overview",
		Active: "home",
		Host:   host,
	}

	// Get latest scan
	scanID, err := s.db.GetLatestScanID()
	if err == nil && scanID != "" {
		scan, err := s.db.GetScan(scanID)
		if err == nil {
			data.LastScan = scan.Timestamp.Format("2006-01-02 15:04")
			data.Summary = severitySummary{
				Critical: scan.Critical,
				High:     scan.High,
				Medium:   scan.Medium,
				Low:      scan.Low,
				Total:    scan.Total,
			}
		}
		// Recent findings (top 20)
		findings, _ := s.db.GetFindings(scanID)
		if len(findings) > 20 {
			findings = findings[:20]
		}
		data.RecentFindings = findingsToRows(findings)
	} else {
		data.LastScan = "never"
	}

	return data
}

// handleHome renders the dashboard home page.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := s.buildHomeData()
	s.renderPage(w, "home.html", data)
}

// handleFindingsPage renders the findings HTML page.
func (s *Server) handleFindingsPage(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Title:  "Findings",
		Active: "findings",
	}

	scanID, _ := s.db.GetLatestScanID()
	if scanID != "" {
		findings, _ := s.db.GetFindings(scanID)
		data.Findings = findingsToRows(findings)
		data.TotalCount = len(data.Findings)

		// Collect unique scanner names for the filter dropdown.
		seen := make(map[string]bool)
		for _, f := range data.Findings {
			if !seen[f.Scanner] {
				seen[f.Scanner] = true
				data.ScannerNames = append(data.ScannerNames, f.Scanner)
			}
		}
	}

	s.renderPage(w, "findings.html", data)
}

// handleHistoryPage renders the scan history HTML page.
func (s *Server) handleHistoryPage(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Title:  "History",
		Active: "history",
	}

	scans, _ := s.db.GetScans(50)
	data.Scans = scans

	s.renderPage(w, "history.html", data)
}

// handleScannersPage renders the scanner status HTML page.
func (s *Server) handleScannersPage(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Title:  "Scanners",
		Active: "scanners",
	}

	for _, sc := range s.registry.All() {
		info := scannerInfo{
			Name:        sc.Name(),
			Category:    sc.Category(),
			Available:   sc.Available(),
			Description: sc.Description(),
		}
		data.Scanners = append(data.Scanners, info)
		if info.Available {
			data.AvailableCount++
		}
	}
	data.TotalCount = len(data.Scanners)

	data.Tools = s.toolReg.CheckAll()

	s.renderPage(w, "scanners.html", data)
}

// handleSettingsPage renders the settings HTML page.
func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	cfg, _ := loadConfig()
	data := pageData{
		Title:  "Settings",
		Active: "settings",
		Config: cfg,
	}
	s.renderPage(w, "settings.html", data)
}
