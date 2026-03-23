package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// Server is the HTTP server that powers the local security dashboard.
type Server struct {
	db        *DB
	registry  *scanner.Registry
	port      int
	mux       *http.ServeMux
	bgScanner *BackgroundScanner
}

// NewServer creates a Server wired to the given DB and scanner Registry.
func NewServer(db *DB, registry *scanner.Registry, port int) *Server {
	bg := NewBackgroundScanner(db, registry, 6*time.Hour)
	s := &Server{
		db:        db,
		registry:  registry,
		port:      port,
		mux:       http.NewServeMux(),
		bgScanner: bg,
	}
	s.setupRoutes()
	return s
}

// Start begins listening on 127.0.0.1:{port}.  It starts the background scanner,
// then blocks until the server returns an error (e.g. the listener is closed).
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

	// Static assets.
	s.mux.Handle("/static/", http.FileServer(http.FS(StaticFS)))

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

// handleHome renders the dashboard home page.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Defense Kit Dashboard</title></head>
<body>
<h1>Defense Kit Dashboard</h1>
<nav>
  <a href="/findings">Findings</a> |
  <a href="/history">History</a> |
  <a href="/scanners">Scanners</a> |
  <a href="/settings">Settings</a>
</nav>
<p>API endpoints: <a href="/api/status">/api/status</a></p>
</body></html>`)
}

// handleFindingsPage renders the findings HTML page.
func (s *Server) handleFindingsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Findings — Defense Kit</title></head>
<body><h1>Findings</h1>
<p>See <a href="/api/findings">/api/findings</a> for JSON data.</p>
</body></html>`)
}

// handleHistoryPage renders the scan history HTML page.
func (s *Server) handleHistoryPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Scan History — Defense Kit</title></head>
<body><h1>Scan History</h1>
<p>See <a href="/api/history">/api/history</a> for JSON data.</p>
</body></html>`)
}

// handleScannersPage renders the scanner status HTML page.
func (s *Server) handleScannersPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Scanners — Defense Kit</title></head>
<body><h1>Scanners</h1>
<p>See <a href="/api/scanners">/api/scanners</a> for JSON data.</p>
</body></html>`)
}

// handleSettingsPage renders the settings HTML page.
func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Settings — Defense Kit</title></head>
<body><h1>Settings</h1>
<p>See <a href="/api/settings">/api/settings</a> for JSON data.</p>
</body></html>`)
}
