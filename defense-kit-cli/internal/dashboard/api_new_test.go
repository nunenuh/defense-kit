package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// ensure unused import doesn't cause a compile error
var _ = bytes.NewReader
