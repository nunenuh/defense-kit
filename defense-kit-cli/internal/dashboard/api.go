package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
