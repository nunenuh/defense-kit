package dashboard

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/hardener"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
)

// writeJSON marshals v to JSON and writes it to w with a 200 status.
// On marshal error a 500 is returned.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// apiStatusResponse is the payload for GET /api/status.
type apiStatusResponse struct {
	Host              string     `json:"host"`
	LastScanID        string     `json:"last_scan_id,omitempty"`
	LastScanAt        *time.Time `json:"last_scan_at,omitempty"`
	Summary           *ScanRecord `json:"summary,omitempty"`
	UnreadNotifCount  int        `json:"unread_notifications"`
}

// handleAPIStatus returns overall system status.
func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()

	resp := apiStatusResponse{Host: host}

	latestID, err := s.db.GetLatestScanID()
	if err == nil && latestID != "" {
		resp.LastScanID = latestID
		if rec, err := s.db.GetScan(latestID); err == nil {
			resp.LastScanAt = &rec.Timestamp
			resp.Summary = &rec
		}
	}

	notifs, err := s.db.GetNotifications(true)
	if err == nil {
		resp.UnreadNotifCount = len(notifs)
	}

	writeJSON(w, resp)
}

// handleAPIFindings returns a paginated, optionally-filtered list of findings.
//
// Query parameters:
//
//	severity   int    (-1 = all, default -1)
//	scanner    string (empty = all)
//	limit      int    (default 50)
//	offset     int    (default 0)
func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	severity := -1
	if sv := q.Get("severity"); sv != "" {
		if n, err := strconv.Atoi(sv); err == nil {
			severity = n
		}
	}

	scannerName := q.Get("scanner")

	limit := 50
	if lv := q.Get("limit"); lv != "" {
		if n, err := strconv.Atoi(lv); err == nil && n > 0 {
			limit = n
		}
	}

	offset := 0
	if ov := q.Get("offset"); ov != "" {
		if n, err := strconv.Atoi(ov); err == nil && n >= 0 {
			offset = n
		}
	}

	findings, total, err := s.db.GetAllFindings(severity, scannerName, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// handleAPIHistory returns the list of scan summary records.
//
// Query parameters:
//
//	limit  int (default 20)
func (s *Server) handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if lv := r.URL.Query().Get("limit"); lv != "" {
		if n, err := strconv.Atoi(lv); err == nil && n > 0 {
			limit = n
		}
	}

	scans, err := s.db.GetScans(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"scans": scans,
		"total": len(scans),
	})
}

// handleAPITrend returns daily severity counts for a configurable window.
//
// Query parameters:
//
//	days  int (default 30)
func (s *Server) handleAPITrend(w http.ResponseWriter, r *http.Request) {
	days := 30
	if dv := r.URL.Query().Get("days"); dv != "" {
		if n, err := strconv.Atoi(dv); err == nil && n > 0 {
			days = n
		}
	}

	trend, err := s.db.GetTrend(days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"trend": trend,
		"days":  days,
	})
}

// scannerStatus describes a single scanner's availability.
type scannerStatus struct {
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Description   string   `json:"description"`
	Available     bool     `json:"available"`
	RequiresRoot  bool     `json:"requires_root"`
	RequiredTools []string `json:"required_tools"`
	OptionalTools []string `json:"optional_tools"`
}

// handleAPIScanners returns the status of every registered scanner.
func (s *Server) handleAPIScanners(w http.ResponseWriter, r *http.Request) {
	all := s.registry.All()
	statuses := make([]scannerStatus, 0, len(all))
	for _, sc := range all {
		statuses = append(statuses, scannerStatus{
			Name:          sc.Name(),
			Category:      sc.Category(),
			Description:   sc.Description(),
			Available:     sc.Available(),
			RequiresRoot:  sc.RequiresRoot(),
			RequiredTools: sc.RequiredTools(),
			OptionalTools: sc.OptionalTools(),
		})
	}

	writeJSON(w, map[string]interface{}{
		"scanners": statuses,
		"total":    len(statuses),
	})
}

// scanTriggerResponse is returned immediately when a scan is triggered.
type scanTriggerResponse struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
}

// handleAPIScan triggers a background scan and returns the scan ID immediately.
func (s *Server) handleAPIScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	scanID := generateScanID()
	host, _ := os.Hostname()

	// Persist a "running" record right away so callers can poll.
	record := ScanRecord{
		ID:        scanID,
		Timestamp: time.Now().UTC(),
		Host:      host,
		Status:    "running",
	}
	if err := s.db.SaveScan(record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scan record: "+err.Error())
		return
	}

	go func() {
		start := time.Now()

		eng := scanner.NewEngine(s.registry)
		opts := scanner.ScanOptions{
			Timeout:     60 * time.Second,
			Concurrency: 4,
			ToolRunner:  tools.NewRunner(),
		}
		results := eng.Run(context.Background(), opts)

		// Collect all findings.
		var allFindings []scanner.Finding
		for _, res := range results {
			allFindings = append(allFindings, res.Findings...)
		}

		// Count by severity.
		rec := ScanRecord{
			ID:        scanID,
			Timestamp: record.Timestamp,
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

		_ = s.db.SaveScan(rec)
		_ = s.db.SaveFindings(scanID, allFindings)

		// Add a notification if critical findings were found.
		if rec.Critical > 0 {
			_ = s.db.AddNotification(Notification{
				Timestamp: time.Now().UTC(),
				Type:      "scan_complete",
				Severity:  int(scanner.SevCritical),
				Title:     fmt.Sprintf("Scan %s: %d critical findings", scanID, rec.Critical),
				Body:      fmt.Sprintf("Scan completed with %d total findings (%d critical, %d high, %d medium, %d low).", rec.Total, rec.Critical, rec.High, rec.Medium, rec.Low),
			})
		}
	}()

	writeJSON(w, scanTriggerResponse{ScanID: scanID, Status: "running"})
}

// handleAPINotificationRead marks a notification as read.
// Expects path: /api/notifications/read/{id}
func (s *Server) handleAPINotificationRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	// Extract the ID from the path suffix.
	prefix := "/api/notifications/read/"
	idStr := strings.TrimPrefix(r.URL.Path, prefix)
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid notification id")
		return
	}

	if err := s.db.MarkNotificationRead(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]string{"status": "ok"})
}

// handleAPIScanStatus returns the current status of a scan by ID.
// GET /api/scan/status/{id}
func (s *Server) handleAPIScanStatus(w http.ResponseWriter, r *http.Request) {
	prefix := "/api/scan/status/"
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if id == "" {
		writeError(w, http.StatusBadRequest, "scan id required")
		return
	}

	rec, err := s.db.GetScan(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}

	writeJSON(w, map[string]interface{}{
		"scan_id":  rec.ID,
		"status":   rec.Status,
		"total":    rec.Total,
		"critical": rec.Critical,
		"high":     rec.High,
		"medium":   rec.Medium,
		"low":      rec.Low,
	})
}

// handleAPIHardenPreview runs a scan, finds fixable findings, and returns a preview.
// POST /api/harden/preview
func (s *Server) handleAPIHardenPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	eng := scanner.NewEngine(s.registry)
	opts := scanner.ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: 4,
		ToolRunner:  tools.NewRunner(),
	}
	results := eng.Run(context.Background(), opts)

	var allFindings []scanner.Finding
	for _, res := range results {
		allFindings = append(allFindings, res.Findings...)
	}

	reg := hardener.NewHardenerRegistry()
	fixable := reg.FixableFindings(allFindings)

	writeJSON(w, map[string]interface{}{
		"fixable": fixable,
		"total":   len(fixable),
	})
}

// handleAPIBaselineUpdate runs a scan, saves as the current baseline.
// POST /api/baseline/update
func (s *Server) handleAPIBaselineUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	eng := scanner.NewEngine(s.registry)
	opts := scanner.ScanOptions{
		Timeout:     60 * time.Second,
		Concurrency: 4,
		ToolRunner:  tools.NewRunner(),
	}
	results := eng.Run(context.Background(), opts)

	var allFindings []scanner.Finding
	for _, res := range results {
		allFindings = append(allFindings, res.Findings...)
	}

	// Save as a regular scan first so findings are stored.
	scanID := generateScanID()
	host, _ := os.Hostname()
	rec := ScanRecord{
		ID:        scanID,
		Timestamp: time.Now().UTC(),
		Host:      host,
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
	if err := s.db.SaveScan(rec); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.db.SaveFindings(scanID, allFindings); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.db.SaveBaseline(scanID, len(allFindings)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":        "ok",
		"scan_id":       scanID,
		"finding_count": len(allFindings),
	})
}

// handleAPIBaselineStatus returns current baseline info.
// GET /api/baseline/status
func (s *Server) handleAPIBaselineStatus(w http.ResponseWriter, r *http.Request) {
	b, err := s.db.GetBaseline()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if b == nil {
		writeJSON(w, map[string]interface{}{
			"exists": false,
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"exists":        true,
		"scan_id":       b.ScanID,
		"finding_count": b.FindingCount,
		"last_updated":  b.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// scheduleEnableRequest is the body for POST /api/schedule/enable.
type scheduleEnableRequest struct {
	Interval string `json:"interval"`
	Mode     string `json:"mode"`
}

// handleAPIScheduleEnable enables the background schedule.
// POST /api/schedule/enable
func (s *Server) handleAPIScheduleEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req scheduleEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Interval == "" {
		req.Interval = "6h"
	}
	if req.Mode == "" {
		req.Mode = "quick"
	}

	cfg := ScheduleConfig{
		Enabled:   true,
		Interval:  req.Interval,
		Mode:      req.Mode,
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.db.SaveScheduleConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Apply to running background scanner if present.
	if s.bgScanner != nil {
		dur, err := parseDuration(req.Interval)
		if err == nil {
			s.bgScanner.SetInterval(dur)
		}
		if !s.bgScanner.IsRunning() {
			s.bgScanner.Start()
		}
	}

	writeJSON(w, map[string]string{"status": "enabled"})
}

// handleAPIScheduleDisable disables the background schedule.
// POST /api/schedule/disable
func (s *Server) handleAPIScheduleDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	cfg := ScheduleConfig{
		Enabled:   false,
		Interval:  "6h",
		Mode:      "quick",
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.db.SaveScheduleConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if s.bgScanner != nil && s.bgScanner.IsRunning() {
		s.bgScanner.Stop()
	}

	writeJSON(w, map[string]string{"status": "disabled"})
}

// handleAPIScheduleStatus returns the current schedule status.
// GET /api/schedule/status
func (s *Server) handleAPIScheduleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.db.GetScheduleConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	running := false
	if s.bgScanner != nil {
		running = s.bgScanner.IsRunning()
	}

	writeJSON(w, map[string]interface{}{
		"enabled":    cfg.Enabled,
		"interval":   cfg.Interval,
		"mode":       cfg.Mode,
		"running":    running,
		"updated_at": cfg.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

// handleAPINotifications returns unread notifications.
// GET /api/notifications
func (s *Server) handleAPINotifications(w http.ResponseWriter, r *http.Request) {
	notifs, err := s.db.GetNotifications(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"notifications": notifs,
		"total":         len(notifs),
	})
}

// handleAPINotificationsCount returns count of unread notifications.
// GET /api/notifications/count
func (s *Server) handleAPINotificationsCount(w http.ResponseWriter, r *http.Request) {
	notifs, err := s.db.GetNotifications(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int{"unread": len(notifs)})
}

// DashboardConfig is the structure persisted to ~/.config/defense-kit/config.yml.
type DashboardConfig struct {
	Concurrency    int      `yaml:"concurrency"    json:"concurrency"`
	TimeoutSeconds int      `yaml:"timeout_seconds" json:"timeout_seconds"`
	ExcludePaths   []string `yaml:"exclude_paths"  json:"exclude_paths"`
	AlertChannels  []string `yaml:"alert_channels" json:"alert_channels"`
}

// configFilePath returns the path to the config YAML.
func configFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "defense-kit", "config.yml")
	}
	return filepath.Join(home, ".config", "defense-kit", "config.yml")
}

// loadConfig reads the config file; returns defaults if file is absent.
func loadConfig() (DashboardConfig, error) {
	cfg := DashboardConfig{
		Concurrency:    4,
		TimeoutSeconds: 60,
		ExcludePaths:   []string{},
		AlertChannels:  []string{},
	}
	data, err := os.ReadFile(configFilePath())
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// saveConfig writes cfg to the config YAML file.
func saveConfig(cfg DashboardConfig) error {
	path := configFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// handleAPISettings dispatches GET /api/settings and POST /api/settings.
func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAPIGetSettings(w, r)
	case http.MethodPost:
		s.handleAPIPostSettings(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

// handleAPIGetSettings returns the current config.
// GET /api/settings
func (s *Server) handleAPIGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, cfg)
}

// handleAPIPostSettings applies a partial or full config update.
// POST /api/settings
func (s *Server) handleAPIPostSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	current, err := loadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read config: "+err.Error())
		return
	}

	// Decode partial update — only set fields that are present.
	var patch DashboardConfig
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if patch.Concurrency > 0 {
		current.Concurrency = patch.Concurrency
	}
	if patch.TimeoutSeconds > 0 {
		current.TimeoutSeconds = patch.TimeoutSeconds
	}
	if patch.ExcludePaths != nil {
		current.ExcludePaths = patch.ExcludePaths
	}
	if patch.AlertChannels != nil {
		current.AlertChannels = patch.AlertChannels
	}

	if err := saveConfig(current); err != nil {
		writeError(w, http.StatusInternalServerError, "save config: "+err.Error())
		return
	}
	writeJSON(w, current)
}

// handleAPIExport exports findings for a scan as CSV.
// GET /api/export/{scan_id}?format=csv
func (s *Server) handleAPIExport(w http.ResponseWriter, r *http.Request) {
	prefix := "/api/export/"
	scanID := strings.TrimPrefix(r.URL.Path, prefix)
	if scanID == "" {
		writeError(w, http.StatusBadRequest, "scan id required")
		return
	}

	// Verify the scan exists.
	if _, err := s.db.GetScan(scanID); err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}

	findings, err := s.db.GetFindings(scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	filename := fmt.Sprintf("defense-kit-%s.csv", scanID)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "scanner", "severity", "title", "detail", "evidence", "location", "remediation", "can_auto_fix"})
	for _, f := range findings {
		canFix := "false"
		if f.CanAutoFix {
			canFix = "true"
		}
		_ = cw.Write([]string{
			f.ID,
			f.Scanner,
			f.Severity.String(),
			f.Title,
			f.Detail,
			f.Evidence,
			f.Location,
			f.Remediation,
			canFix,
		})
	}
	cw.Flush()
}

// parseDuration parses a duration string like "6h", "30m", "1h30m".
// Falls back to time.ParseDuration for standard Go formats.
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// generateScanID creates a unique scan identifier using the current timestamp.
func generateScanID() string {
	home, _ := os.UserHomeDir()
	_ = home
	return fmt.Sprintf("scan-%s", time.Now().UTC().Format("20060102-150405.000000000"))
}

// dbPath returns the default path for the dashboard SQLite database.
func dbPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".defense-kit", "dashboard.db")
	}
	return filepath.Join(home, ".defense-kit", "dashboard.db")
}
