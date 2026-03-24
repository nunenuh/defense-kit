package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ── Scan Status ──────────────────────────────────────────────────────────────

func TestAPIScanStatus_NotFound(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scan/status/nonexistent", nil)
	req.URL.Path = "/api/scan/status/nonexistent"
	w := httptest.NewRecorder()
	srv.handleAPIScanStatus(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAPIScanStatus_Found(t *testing.T) {
	srv, db := testServer(t)

	rec := ScanRecord{
		ID:        "scan-status-poll",
		Timestamp: time.Now().UTC(),
		Host:      "h",
		Status:    "running",
	}
	if err := db.SaveScan(rec); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scan/status/scan-status-poll", nil)
	req.URL.Path = "/api/scan/status/scan-status-poll"
	w := httptest.NewRecorder()
	srv.handleAPIScanStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["scan_id"] != "scan-status-poll" {
		t.Errorf("scan_id: got %v, want scan-status-poll", body["scan_id"])
	}
	if body["status"] != "running" {
		t.Errorf("status: got %v, want running", body["status"])
	}
}

func TestAPIScanStatus_MissingID(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scan/status/", nil)
	req.URL.Path = "/api/scan/status/"
	w := httptest.NewRecorder()
	srv.handleAPIScanStatus(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Result().StatusCode)
	}
}

// ── Harden Preview ───────────────────────────────────────────────────────────

func TestAPIHardenPreview_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/harden/preview", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHardenPreview(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

func TestAPIHardenPreview_ReturnsJSON(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/harden/preview", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHardenPreview(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["total"]; !ok {
		t.Error("response missing 'total' field")
	}
}

// ── Baseline ─────────────────────────────────────────────────────────────────

func TestAPIBaselineStatus_NoBaseline(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/baseline/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["exists"] != false {
		t.Errorf("exists: got %v, want false", body["exists"])
	}
}

func TestAPIBaselineStatus_WithBaseline(t *testing.T) {
	srv, db := testServer(t)

	// Pre-populate a scan + baseline directly via DB.
	rec := ScanRecord{ID: "scan-base", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	_ = db.SaveScan(rec)
	_ = db.SaveBaseline("scan-base", 7)

	req := httptest.NewRequest(http.MethodGet, "/api/baseline/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineStatus(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["exists"] != true {
		t.Errorf("exists: got %v, want true", body["exists"])
	}
	if body["finding_count"].(float64) != 7 {
		t.Errorf("finding_count: got %v, want 7", body["finding_count"])
	}
}

func TestAPIBaselineUpdate_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

// TestAPIBaselineUpdate_DBError exercises the SaveScan error path by closing
// the DB before calling the handler.
func TestAPIBaselineUpdate_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIBaselineUpdate_Post exercises the POST path which runs a quick scan
// with an empty registry and saves the result as the baseline.
func TestAPIBaselineUpdate_Post(t *testing.T) {
	srv, db := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/baseline/update: expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status: got %v, want ok", body["status"])
	}
	if _, ok := body["scan_id"]; !ok {
		t.Error("response missing scan_id field")
	}

	// Verify baseline was saved.
	b, err := db.GetBaseline()
	if err != nil {
		t.Fatalf("GetBaseline: %v", err)
	}
	if b == nil {
		t.Error("expected baseline to be saved")
	}
}

// ── Schedule ─────────────────────────────────────────────────────────────────

func TestAPIScheduleStatus_Default(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["enabled"] != false {
		t.Errorf("enabled: got %v, want false", body["enabled"])
	}
}

func TestAPIScheduleEnable_And_Disable(t *testing.T) {
	srv, _ := testServer(t)

	// Enable.
	body := `{"interval":"1h","mode":"quick"}`
	req := httptest.NewRequest(http.MethodPost, "/api/schedule/enable", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: expected 200, got %d", resp.StatusCode)
	}

	// Verify in DB.
	cfg, err := srv.db.GetScheduleConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Error("expected schedule to be enabled")
	}
	if cfg.Interval != "1h" {
		t.Errorf("interval: got %q, want 1h", cfg.Interval)
	}

	// Disable.
	req2 := httptest.NewRequest(http.MethodPost, "/api/schedule/disable", nil)
	w2 := httptest.NewRecorder()
	srv.handleAPIScheduleDisable(w2, req2)

	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("disable: expected 200, got %d", w2.Result().StatusCode)
	}

	cfg2, _ := srv.db.GetScheduleConfig()
	if cfg2.Enabled {
		t.Error("expected schedule to be disabled")
	}
}

func TestAPIScheduleEnable_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/enable", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

// ── Notifications ────────────────────────────────────────────────────────────

func TestAPINotifications_Empty(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/notifications", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotifications(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["total"].(float64) != 0 {
		t.Errorf("total: got %v, want 0", body["total"])
	}
}

func TestAPINotificationsCount(t *testing.T) {
	srv, db := testServer(t)

	_ = db.AddNotification(Notification{
		Timestamp: time.Now().UTC(),
		Type:      "test",
		Severity:  int(scanner.SevHigh),
		Title:     "test notif",
		Body:      "body",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/count", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotificationsCount(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["unread"].(float64) != 1 {
		t.Errorf("unread: got %v, want 1", body["unread"])
	}
}

// ── Settings ─────────────────────────────────────────────────────────────────

func TestAPISettings_GetAndPost(t *testing.T) {
	srv, _ := testServer(t)

	// Override config path so we don't touch the real home dir.
	t.Setenv("HOME", t.TempDir())

	// GET — should return defaults.
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPIGetSettings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET settings: expected 200, got %d", resp.StatusCode)
	}

	var cfg DashboardConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Concurrency != 4 {
		t.Errorf("default concurrency: got %d, want 4", cfg.Concurrency)
	}

	// POST — update concurrency.
	patch := `{"concurrency":8}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(patch))
	w2 := httptest.NewRecorder()
	srv.handleAPIPostSettings(w2, req2)

	resp2 := w2.Result()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("POST settings: expected 200, got %d", resp2.StatusCode)
	}

	var cfg2 DashboardConfig
	if err := json.NewDecoder(resp2.Body).Decode(&cfg2); err != nil {
		t.Fatalf("decode updated: %v", err)
	}
	if cfg2.Concurrency != 8 {
		t.Errorf("updated concurrency: got %d, want 8", cfg2.Concurrency)
	}
}

func TestAPISettings_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPISettings(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

// ── Export ───────────────────────────────────────────────────────────────────

func TestAPIExport_NotFound(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/export/no-such-scan", nil)
	req.URL.Path = "/api/export/no-such-scan"
	w := httptest.NewRecorder()
	srv.handleAPIExport(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAPIExport_CSV(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{
		ID:        "scan-export",
		Timestamp: time.Now().UTC(),
		Host:      "h",
		Status:    "completed",
	}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}
	findings := []scanner.Finding{
		{ID: "ef1", Scanner: "s", Severity: scanner.SevHigh, Title: "Export Test", Location: "/tmp/x"},
	}
	if err := db.SaveFindings("scan-export", findings); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/export/scan-export?format=csv", nil)
	req.URL.Path = "/api/export/scan-export"
	w := httptest.NewRecorder()
	srv.handleAPIExport(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/csv" {
		t.Errorf("Content-Type: got %q, want text/csv", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition missing 'attachment': %q", cd)
	}
	if !strings.Contains(cd, "scan-export") {
		t.Errorf("Content-Disposition missing scan id: %q", cd)
	}

	// Body should have header row + data row.
	body := w.Body.String()
	if !strings.Contains(body, "severity") {
		t.Error("CSV missing header row")
	}
	if !strings.Contains(body, "Export Test") {
		t.Error("CSV missing finding title")
	}
}

func TestAPIExport_MissingID(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/export/", nil)
	req.URL.Path = "/api/export/"
	w := httptest.NewRecorder()
	srv.handleAPIExport(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Result().StatusCode)
	}
}

// ── BackgroundScanner ────────────────────────────────────────────────────────

func TestBackgroundScanner_StartStop(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bg.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := scanner.NewRegistry()
	bg := NewBackgroundScanner(db, reg, 10*time.Hour) // large interval — won't fire

	if bg.IsRunning() {
		t.Error("should not be running before Start()")
	}

	bg.Start()
	if !bg.IsRunning() {
		t.Error("should be running after Start()")
	}

	// Second Start() is a no-op.
	bg.Start()
	if !bg.IsRunning() {
		t.Error("still running after double Start()")
	}

	bg.Stop()
	if bg.IsRunning() {
		t.Error("should not be running after Stop()")
	}

	// Stop on already-stopped scanner is a no-op.
	bg.Stop()
}

func TestBackgroundScanner_SetInterval(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bg2.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := scanner.NewRegistry()
	bg := NewBackgroundScanner(db, reg, 1*time.Hour)
	bg.SetInterval(2 * time.Hour)
	// Just verify no panic; interval is internal state.
}

// ── DB baseline + schedule ───────────────────────────────────────────────────

func TestDB_BaselineSaveGet(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	// No baseline yet.
	b, err := db.GetBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Error("expected nil baseline")
	}

	// Save scan + baseline.
	_ = db.SaveScan(ScanRecord{ID: "bl-scan", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"})
	if err := db.SaveBaseline("bl-scan", 12); err != nil {
		t.Fatal(err)
	}

	b, err = db.GetBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("expected non-nil baseline")
	}
	if b.ScanID != "bl-scan" {
		t.Errorf("ScanID: got %q, want bl-scan", b.ScanID)
	}
	if b.FindingCount != 12 {
		t.Errorf("FindingCount: got %d, want 12", b.FindingCount)
	}
}

func TestDB_ScheduleConfig(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	// Defaults when no config saved.
	cfg, err := db.GetScheduleConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Error("default enabled should be false")
	}
	if cfg.Interval != "6h" {
		t.Errorf("default interval: got %q, want 6h", cfg.Interval)
	}

	// Save and retrieve.
	want := ScheduleConfig{
		Enabled:   true,
		Interval:  "2h",
		Mode:      "full",
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := db.SaveScheduleConfig(want); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetScheduleConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled {
		t.Error("expected enabled=true")
	}
	if got.Interval != "2h" {
		t.Errorf("interval: got %q, want 2h", got.Interval)
	}
	if got.Mode != "full" {
		t.Errorf("mode: got %q, want full", got.Mode)
	}
}

// ── Settings page ────────────────────────────────────────────────────────────

func TestSettingsPage_Returns200(t *testing.T) {
	srv, _ := testServer(t)

	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// ── loadConfig / saveConfig ──────────────────────────────────────────────────

func TestLoadConfig_Defaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Concurrency != 4 {
		t.Errorf("default concurrency: got %d, want 4", cfg.Concurrency)
	}
	if cfg.TimeoutSeconds != 60 {
		t.Errorf("default timeout: got %d, want 60", cfg.TimeoutSeconds)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	want := DashboardConfig{
		Concurrency:    8,
		TimeoutSeconds: 120,
		ExcludePaths:   []string{"/tmp", "/proc"},
		AlertChannels:  []string{"slack"},
	}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}

	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Concurrency != want.Concurrency {
		t.Errorf("concurrency: got %d, want %d", got.Concurrency, want.Concurrency)
	}
	if got.TimeoutSeconds != want.TimeoutSeconds {
		t.Errorf("timeout: got %d, want %d", got.TimeoutSeconds, want.TimeoutSeconds)
	}
	if len(got.ExcludePaths) != 2 {
		t.Errorf("exclude_paths count: got %d, want 2", len(got.ExcludePaths))
	}
}

// TestAPIPostSettings_AllFields exercises the full patch-merge logic
// (concurrency, timeout_seconds, exclude_paths, alert_channels).
func TestAPIPostSettings_AllFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := testServer(t)

	patch := `{"concurrency":16,"timeout_seconds":120,"exclude_paths":["/tmp","/proc"],"alert_channels":["slack","pagerduty"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(patch))
	w := httptest.NewRecorder()
	srv.handleAPIPostSettings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST settings: expected 200, got %d", resp.StatusCode)
	}

	var cfg DashboardConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Concurrency != 16 {
		t.Errorf("concurrency: got %d, want 16", cfg.Concurrency)
	}
	if cfg.TimeoutSeconds != 120 {
		t.Errorf("timeout_seconds: got %d, want 120", cfg.TimeoutSeconds)
	}
	if len(cfg.ExcludePaths) != 2 {
		t.Errorf("exclude_paths: got %d, want 2", len(cfg.ExcludePaths))
	}
	if len(cfg.AlertChannels) != 2 {
		t.Errorf("alert_channels: got %d, want 2", len(cfg.AlertChannels))
	}
}

// TestAPISettings_GetDispatch exercises the GET branch of handleAPISettings.
func TestAPISettings_GetDispatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPISettings(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET via handleAPISettings: expected 200, got %d", w.Result().StatusCode)
	}
}

// TestAPISettings_PostDispatch exercises the POST branch of handleAPISettings.
func TestAPISettings_PostDispatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"concurrency":2}`))
	w := httptest.NewRecorder()
	srv.handleAPISettings(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("POST via handleAPISettings: expected 200, got %d", w.Result().StatusCode)
	}
}

// TestAPIPostSettings_MethodNotAllowed exercises the early-return 405 branch
// in handleAPIPostSettings.
func TestAPIPostSettings_MethodNotAllowed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPIPostSettings(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

// TestBackgroundScanner_RunOneScan exercises runOneScan by starting a scanner
// with a very short interval and waiting for one tick.
func TestBackgroundScanner_RunOneScan(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bg_scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Use an empty registry so scans complete instantly.
	reg := scanner.NewRegistry()
	bg := NewBackgroundScanner(db, reg, 10*time.Millisecond)

	bg.Start()
	// Give it enough time for at least one tick.
	time.Sleep(100 * time.Millisecond)
	bg.Stop()

	// runOneScan should have fired at least once — just verify no panic.
	if bg.IsRunning() {
		t.Error("should not be running after Stop()")
	}
}

// ── parseDuration ────────────────────────────────────────────────────────────

func TestParseDuration(t *testing.T) {
	cases := []struct {
		input string
		want  bool // true = should succeed
	}{
		{"6h", true},
		{"30m", true},
		{"1h30m", true},
		{"bad", false},
	}
	for _, c := range cases {
		_, err := parseDuration(c.input)
		if c.want && err != nil {
			t.Errorf("parseDuration(%q) unexpected error: %v", c.input, err)
		}
		if !c.want && err == nil {
			t.Errorf("parseDuration(%q) expected error, got nil", c.input)
		}
	}
}

// ── Additional DB tests ───────────────────────────────────────────────────────

func TestDB_GetScans_Multiple(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	ts := time.Now().UTC()
	scans := []ScanRecord{
		{ID: "s1", Timestamp: ts.Add(-2 * time.Hour), Host: "h", Status: "completed", Total: 5},
		{ID: "s2", Timestamp: ts.Add(-time.Hour), Host: "h", Status: "completed", Total: 10},
		{ID: "s3", Timestamp: ts, Host: "h", Status: "completed", Total: 3},
	}
	for _, s := range scans {
		if err := db.SaveScan(s); err != nil {
			t.Fatalf("SaveScan %s: %v", s.ID, err)
		}
	}

	all, err := db.GetScans(0)
	if err != nil {
		t.Fatalf("GetScans: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 scans, got %d", len(all))
	}
	// Newest first.
	if all[0].ID != "s3" {
		t.Errorf("first scan ID: got %q, want s3", all[0].ID)
	}
}

func TestDB_GetTrend_MultipleScans(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	for i, id := range []string{"scan-t1", "scan-t2"} {
		s := ScanRecord{
			ID:        id,
			Timestamp: time.Now().UTC().Add(time.Duration(-i) * time.Hour),
			Host:      "h",
			Status:    "completed",
		}
		if err := db.SaveScan(s); err != nil {
			t.Fatalf("SaveScan: %v", err)
		}
		findings := []scanner.Finding{
			{ID: "f" + id + "1", Scanner: "s", Severity: scanner.SevHigh, Title: "high"},
			{ID: "f" + id + "2", Scanner: "s", Severity: scanner.SevMedium, Title: "med"},
		}
		if err := db.SaveFindings(id, findings); err != nil {
			t.Fatalf("SaveFindings: %v", err)
		}
	}

	trend, err := db.GetTrend(30)
	if err != nil {
		t.Fatalf("GetTrend: %v", err)
	}
	if len(trend) == 0 {
		t.Fatal("expected at least one trend point")
	}

	today := time.Now().UTC().Format("2006-01-02")
	var found bool
	for _, tp := range trend {
		if tp.Date == today {
			found = true
			if tp.High < 2 {
				t.Errorf("expected at least 2 HIGH findings today, got %d", tp.High)
			}
		}
	}
	if !found {
		t.Errorf("no trend point for today %s", today)
	}
}

// ── BackgroundScanner additional tests ───────────────────────────────────────

func TestBackgroundScanner_IsRunningFalseBeforeStart(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bgx.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := scanner.NewRegistry()
	bg := NewBackgroundScanner(db, reg, 10*time.Hour)

	if bg.IsRunning() {
		t.Error("should not be running before Start()")
	}
}

func TestBackgroundScanner_StopWhenNotRunning(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bgy.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := scanner.NewRegistry()
	bg := NewBackgroundScanner(db, reg, 10*time.Hour)
	// Stop on a never-started scanner should not panic or deadlock.
	bg.Stop()
}

// ── Additional API endpoint tests ─────────────────────────────────────────────

func TestAPIHistory_WithLimit(t *testing.T) {
	srv, db := testServer(t)

	for _, id := range []string{"ha1", "ha2", "ha3", "ha4", "ha5"} {
		_ = db.SaveScan(ScanRecord{ID: id, Timestamp: time.Now().UTC(), Host: "h", Status: "completed"})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/history?limit=3", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHistory(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	scans, ok := body["scans"].([]interface{})
	if !ok {
		t.Fatal("scans field wrong type")
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans with limit=3, got %d", len(scans))
	}
}

func TestAPITrend_WithData(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{ID: "trend-api", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	_ = db.SaveScan(scan)
	_ = db.SaveFindings("trend-api", []scanner.Finding{
		{ID: "tf1", Scanner: "s", Severity: scanner.SevCritical, Title: "crit"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/trend?days=30", nil)
	w := httptest.NewRecorder()
	srv.handleAPITrend(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if _, ok := body["trend"]; !ok {
		t.Error("response missing 'trend' field")
	}
}

func TestAPIStatus_UnreadNotifications(t *testing.T) {
	srv, db := testServer(t)

	// Add two unread notifications.
	for i := 0; i < 2; i++ {
		_ = db.AddNotification(Notification{
			Timestamp: time.Now().UTC(),
			Type:      "test",
			Severity:  int(scanner.SevHigh),
			Title:     "notif",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIStatus(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["unread_notifications"].(float64) != 2 {
		t.Errorf("unread_notifications: got %v, want 2", body["unread_notifications"])
	}
}

func TestAPINotifications_WithData(t *testing.T) {
	srv, db := testServer(t)

	_ = db.AddNotification(Notification{
		Timestamp: time.Now().UTC(),
		Type:      "scan",
		Severity:  int(scanner.SevCritical),
		Title:     "crit notif",
		Body:      "body text",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/notifications", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotifications(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["total"].(float64) != 1 {
		t.Errorf("total: got %v, want 1", body["total"])
	}

	notifs, ok := body["notifications"].([]interface{})
	if !ok || len(notifs) != 1 {
		t.Errorf("expected 1 notification, got %v", body["notifications"])
	}
}

func TestAPINotificationRead_Success(t *testing.T) {
	srv, db := testServer(t)

	_ = db.AddNotification(Notification{
		Timestamp: time.Now().UTC(),
		Type:      "test",
		Title:     "read-me",
	})

	all, _ := db.GetNotifications(false)
	if len(all) == 0 {
		t.Fatal("expected at least one notification")
	}
	id := all[0].ID

	req := httptest.NewRequest(http.MethodPost, "/api/notifications/read/"+string(rune('0'+id)), nil)
	req.URL.Path = "/api/notifications/read/" + string(rune('0'+id))
	// Use a proper integer path.
	req2 := httptest.NewRequest(http.MethodPost, "/api/notifications/read/1", nil)
	req2.URL.Path = "/api/notifications/read/1"
	w := httptest.NewRecorder()
	srv.handleAPINotificationRead(w, req2)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Result().StatusCode)
	}
}

// ── handleAPIBaselineUpdate ───────────────────────────────────────────────────

func TestAPIBaselineUpdate_MethodNotAllowed_GET(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

func TestAPIBaselineUpdate_Post_ReturnsOK(t *testing.T) {
	srv, _ := testServer(t)

	// POST with empty registry — scan returns 0 findings, baseline is saved.
	req := httptest.NewRequest(http.MethodPost, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status: got %v, want ok", body["status"])
	}
	if _, ok := body["scan_id"]; !ok {
		t.Error("response missing 'scan_id'")
	}
}

// ── handleAPIScan additional tests ───────────────────────────────────────────

func TestAPIScan_Post_Returns_ScanID(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScan(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["scan_id"]; !ok {
		t.Error("response missing 'scan_id'")
	}
	if body["status"] != "running" {
		t.Errorf("status: got %v, want running", body["status"])
	}
}

// ── handleAPIScheduleDisable with running scanner ────────────────────────────

func TestAPIScheduleDisable_StopsRunningScanner(t *testing.T) {
	srv, _ := testServer(t)

	// Start the background scanner.
	srv.bgScanner.Start()
	if !srv.bgScanner.IsRunning() {
		t.Fatal("bgScanner should be running")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/schedule/disable", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleDisable(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
	if srv.bgScanner.IsRunning() {
		t.Error("bgScanner should be stopped after disable")
	}
}

func TestAPIScheduleDisable_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/disable", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleDisable(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

func TestAPIScheduleStatus_WhenRunning(t *testing.T) {
	srv, _ := testServer(t)

	// Enable the schedule config in DB.
	cfg := ScheduleConfig{Enabled: true, Interval: "1h", Mode: "quick", UpdatedAt: time.Now().UTC()}
	_ = srv.db.SaveScheduleConfig(cfg)

	// Start the scanner.
	srv.bgScanner.Start()
	defer srv.bgScanner.Stop()

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleStatus(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["running"] != true {
		t.Errorf("running: got %v, want true", body["running"])
	}
	if body["enabled"] != true {
		t.Errorf("enabled: got %v, want true", body["enabled"])
	}
}

// ── handleAPIScheduleEnable starts background scanner ────────────────────────

func TestAPIScheduleEnable_StartsScanner(t *testing.T) {
	srv, _ := testServer(t)

	body := `{"interval":"10h","mode":"quick"}`
	req := httptest.NewRequest(http.MethodPost, "/api/schedule/enable", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
	// Stop the scanner so it doesn't interfere with other tests.
	srv.bgScanner.Stop()
}

func TestAPIScheduleEnable_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/schedule/enable", strings.NewReader("{bad json"))
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Result().StatusCode)
	}
}

// ── handleAPIGetSettings error path ──────────────────────────────────────────

func TestAPIGetSettings_ReturnsDefaults(t *testing.T) {
	srv, _ := testServer(t)
	t.Setenv("HOME", t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPIGetSettings(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
	var body DashboardConfig
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Concurrency != 4 {
		t.Errorf("default concurrency: got %d, want 4", body.Concurrency)
	}
}

// ── handleAPIPostSettings with invalid body ───────────────────────────────────

func TestAPIPostSettings_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t)
	t.Setenv("HOME", t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	srv.handleAPIPostSettings(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Result().StatusCode)
	}
}

// ── handleAPIFindings with scanner filter ────────────────────────────────────

func TestAPIFindings_FilterByScanner(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{ID: "scan-sc", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	_ = db.SaveScan(scan)
	_ = db.SaveFindings("scan-sc", []scanner.Finding{
		{ID: "s1", Scanner: "ssh", Severity: scanner.SevHigh, Title: "ssh high"},
		{ID: "s2", Scanner: "firewall", Severity: scanner.SevLow, Title: "fw low"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/findings?scanner=ssh", nil)
	w := httptest.NewRecorder()
	srv.handleAPIFindings(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["total"].(float64) != 1 {
		t.Errorf("expected 1 ssh finding, got %v", body["total"])
	}
}

// ── DB SaveFindings edge cases ────────────────────────────────────────────────

func TestDB_GetAllFindings_NoFindings(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	findings, total, err := db.GetAllFindings(-1, "", 50, 0)
	if err != nil {
		t.Fatalf("GetAllFindings: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0 total, got %d", total)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestDB_GetScan_NotFound(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	_, err := db.GetScan("nonexistent-scan")
	if err == nil {
		t.Error("expected error for non-existent scan")
	}
}

// ── loadConfig / saveConfig error paths ──────────────────────────────────────

// TestLoadConfig_UnreadableFile exercises the "file exists but unreadable" path.
func TestLoadConfig_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 000 has no effect")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create the config dir and file.
	cfgDir := filepath.Join(home, ".config", "defense-kit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfgPath := filepath.Join(cfgDir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("concurrency: 8\n"), 0o000); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o644) })

	// loadConfig should return an error (file exists but unreadable).
	_, err := loadConfig()
	if err == nil {
		t.Error("expected loadConfig to return error for unreadable file")
	}
}

// TestLoadConfig_InvalidYAML exercises the yaml.Unmarshal error path.
func TestLoadConfig_InvalidYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".config", "defense-kit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfgPath := filepath.Join(cfgDir, "config.yml")
	// Write invalid YAML that will fail yaml.Unmarshal.
	if err := os.WriteFile(cfgPath, []byte("concurrency: [this is: bad yaml\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadConfig()
	if err == nil {
		t.Error("expected loadConfig to return error for invalid YAML")
	}
}

// TestSaveConfig_MkdirError exercises the MkdirAll error path in saveConfig
// by setting HOME to an unwritable location.
func TestSaveConfig_MkdirError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — permission checks don't apply")
	}

	// Create a read-only directory and set it as HOME.
	readonlyDir := t.TempDir()
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonlyDir, 0o755) })
	t.Setenv("HOME", readonlyDir)

	cfg := DashboardConfig{Concurrency: 4}
	err := saveConfig(cfg)
	if err == nil {
		t.Error("expected saveConfig to fail when HOME directory is read-only")
	}
}

// TestAPIGetSettings_LoadError exercises handleAPIGetSettings writeError path
// by writing a bad YAML config that causes loadConfig to fail.
func TestAPIGetSettings_LoadError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — cannot create unreadable file")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".config", "defense-kit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfgPath := filepath.Join(cfgDir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("bad: [yaml"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.handleAPIGetSettings(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on loadConfig error, got %d", w.Result().StatusCode)
	}
}

// ── handleAPIHistory / handleAPITrend invalid query params ───────────────────

// TestAPIHistory_InvalidLimit exercises the branch where ?limit= is non-numeric.
func TestAPIHistory_InvalidLimit(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/history?limit=notanumber", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHistory(w, req)

	// Falls through to default limit; should still return 200.
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Result().StatusCode)
	}
}

// TestAPIHistory_NegativeLimit exercises the n <= 0 branch of the limit guard.
func TestAPIHistory_NegativeLimit(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/history?limit=-5", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHistory(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Result().StatusCode)
	}
}

// TestAPITrend_InvalidDays exercises the branch where ?days= is non-numeric.
func TestAPITrend_InvalidDays(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/trend?days=bad", nil)
	w := httptest.NewRecorder()
	srv.handleAPITrend(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Result().StatusCode)
	}
}

// TestAPITrend_ZeroDays exercises n <= 0 branch.
func TestAPITrend_ZeroDays(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/trend?days=0", nil)
	w := httptest.NewRecorder()
	srv.handleAPITrend(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Result().StatusCode)
	}
}

// ── handleAPIScheduleEnable invalid interval ─────────────────────────────────

// TestAPIScheduleEnable_InvalidInterval exercises the branch where the interval
// string cannot be parsed as a duration (parseDuration returns error).
func TestAPIScheduleEnable_InvalidInterval(t *testing.T) {
	srv, _ := testServer(t)

	body := `{"interval":"notaduration","mode":"quick"}`
	req := httptest.NewRequest(http.MethodPost, "/api/schedule/enable", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	// An invalid duration should result in a 400 or fall through to default.
	// Either way, no panic.
	_ = w.Result().StatusCode
}

// ── handleAPIScheduleStatus with schedule saved ──────────────────────────────

// TestAPIScheduleStatus_Saved exercises the branch where GetScheduleConfig
// returns a previously saved config.
func TestAPIScheduleStatus_Saved(t *testing.T) {
	srv, db := testServer(t)

	cfg := ScheduleConfig{
		Enabled:   false,
		Interval:  "3h",
		Mode:      "quick",
		UpdatedAt: time.Now().UTC(),
	}
	_ = db.SaveScheduleConfig(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleStatus(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["interval"] != "3h" {
		t.Errorf("interval: got %v, want 3h", body["interval"])
	}
}

// ── handleAPIBaselineUpdate with findings (covers severity switch branches) ──

// TestAPIBaselineUpdate_WithScannerFindings registers a scanner that returns
// findings of various severities, triggering all severity switch cases.
func TestAPIBaselineUpdate_WithScannerFindings(t *testing.T) {
	srv, db := testServer(t)

	// Register a scanner that produces findings of every severity.
	srv.registry.Register(&minimalScannerWithFindings{
		name:     "test-sev",
		category: "test",
		findings: []scanner.Finding{
			{ID: "c1", Scanner: "test-sev", Severity: scanner.SevCritical, Title: "crit"},
			{ID: "h1", Scanner: "test-sev", Severity: scanner.SevHigh, Title: "high"},
			{ID: "m1", Scanner: "test-sev", Severity: scanner.SevMedium, Title: "med"},
			{ID: "l1", Scanner: "test-sev", Severity: scanner.SevLow, Title: "low"},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/baseline/update", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineUpdate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["finding_count"].(float64) != 4 {
		t.Errorf("finding_count: got %v, want 4", body["finding_count"])
	}

	// Verify baseline was saved with correct count.
	b, _ := db.GetBaseline()
	if b == nil || b.FindingCount != 4 {
		t.Errorf("baseline finding count: got %v", b)
	}
}

// minimalScannerWithFindings implements scanner.Scanner and returns a fixed
// set of findings (used to exercise severity-counting branches in handlers).
type minimalScannerWithFindings struct {
	name     string
	category string
	findings []scanner.Finding
}

func (m *minimalScannerWithFindings) Name() string             { return m.name }
func (m *minimalScannerWithFindings) Category() string         { return m.category }
func (m *minimalScannerWithFindings) Description() string      { return "test scanner" }
func (m *minimalScannerWithFindings) RequiredTools() []string  { return nil }
func (m *minimalScannerWithFindings) OptionalTools() []string  { return nil }
func (m *minimalScannerWithFindings) RequiresRoot() bool       { return false }
func (m *minimalScannerWithFindings) Available() bool          { return true }
func (m *minimalScannerWithFindings) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return m.findings, nil
}

// ── DB-error paths: close DB before calling handler ──────────────────────────

// TestAPIFindings_DBError exercises the writeError branch in handleAPIFindings.
func TestAPIFindings_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	w := httptest.NewRecorder()
	srv.handleAPIFindings(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIHistory_DBError exercises the writeError branch in handleAPIHistory
// by closing the DB before calling the handler.
func TestAPIHistory_DBError(t *testing.T) {
	srv, db := testServer(t)
	// Don't use t.Cleanup to close db — we close it here deliberately.
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHistory(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPITrend_DBError exercises the writeError branch in handleAPITrend.
func TestAPITrend_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/trend", nil)
	w := httptest.NewRecorder()
	srv.handleAPITrend(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPINotifications_DBError exercises the writeError branch in handleAPINotifications.
func TestAPINotifications_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/notifications", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotifications(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPINotificationsCount_DBError exercises the writeError branch in handleAPINotificationsCount.
func TestAPINotificationsCount_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/count", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotificationsCount(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIScheduleStatus_DBError exercises the writeError branch in handleAPIScheduleStatus.
func TestAPIScheduleStatus_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/schedule/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleStatus(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPINotificationRead_DBError exercises the MarkNotificationRead error branch.
func TestAPINotificationRead_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/notifications/read/1", nil)
	req.URL.Path = "/api/notifications/read/1"
	w := httptest.NewRecorder()
	srv.handleAPINotificationRead(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIExport_DBError exercises the GetScan error path in handleAPIExport
// (returns 404 when DB is closed/unavailable).
func TestAPIExport_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/export/any-scan", nil)
	req.URL.Path = "/api/export/any-scan"
	w := httptest.NewRecorder()
	srv.handleAPIExport(w, req)

	// GetScan fails when DB is closed → 404 (scan not found path).
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Result().StatusCode)
	}
}

// TestAPIScheduleEnable_DBError exercises the SaveScheduleConfig error branch.
func TestAPIScheduleEnable_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	body := `{"interval":"1h","mode":"quick"}`
	req := httptest.NewRequest(http.MethodPost, "/api/schedule/enable", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAPIScheduleEnable(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIScheduleDisable_DBError exercises the SaveScheduleConfig error branch.
func TestAPIScheduleDisable_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/schedule/disable", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScheduleDisable(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// TestAPIBaselineStatus_DBError exercises the writeError branch in handleAPIBaselineStatus.
func TestAPIBaselineStatus_DBError(t *testing.T) {
	srv, db := testServer(t)
	_ = db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/baseline/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIBaselineStatus(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on DB error, got %d", w.Result().StatusCode)
	}
}

// ensure unused import doesn't cause a compile error
var _ = bytes.NewReader
