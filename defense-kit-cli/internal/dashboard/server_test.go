package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// testServer creates a Server backed by a fresh in-memory (temp-dir) DB.
func testServer(t *testing.T) (*Server, *DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := scanner.NewRegistry()
	srv := NewServer(db, reg, 0) // port 0 — we use httptest
	return srv, db
}

func TestAPIStatus_ReturnsJSON(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := body["host"]; !ok {
		t.Error("response missing 'host' field")
	}
}

func TestAPIStatus_WithScan(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{
		ID:        "scan-status-test",
		Timestamp: time.Now().UTC(),
		Host:      "myhost",
		Status:    "completed",
		Total:     3,
		Critical:  1,
	}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.handleAPIStatus(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["last_scan_id"] != "scan-status-test" {
		t.Errorf("last_scan_id: got %v, want scan-status-test", body["last_scan_id"])
	}
}

func TestAPIFindings_Paginated(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{ID: "scan-f", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}

	findings := []scanner.Finding{
		{ID: "f1", Scanner: "s", Severity: scanner.SevHigh, Title: "high"},
		{ID: "f2", Scanner: "s", Severity: scanner.SevLow, Title: "low"},
		{ID: "f3", Scanner: "s", Severity: scanner.SevMedium, Title: "med"},
	}
	if err := db.SaveFindings("scan-f", findings); err != nil {
		t.Fatal(err)
	}

	// Request first page of 2.
	req := httptest.NewRequest(http.MethodGet, "/api/findings?limit=2&offset=0", nil)
	w := httptest.NewRecorder()
	srv.handleAPIFindings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["total"].(float64) != 3 {
		t.Errorf("total: got %v, want 3", body["total"])
	}
	page, ok := body["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	if len(page) != 2 {
		t.Errorf("page size: got %d, want 2", len(page))
	}
}

func TestAPIFindings_FilterBySeverity(t *testing.T) {
	srv, db := testServer(t)

	scan := ScanRecord{ID: "scan-sev", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	_ = db.SaveScan(scan)
	_ = db.SaveFindings("scan-sev", []scanner.Finding{
		{ID: "c1", Scanner: "s", Severity: scanner.SevCritical, Title: "crit"},
		{ID: "l1", Scanner: "s", Severity: scanner.SevLow, Title: "low"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/findings?severity=3", nil) // 3 = SevCritical
	w := httptest.NewRecorder()
	srv.handleAPIFindings(w, req)

	var body map[string]interface{}
	_ = json.NewDecoder(w.Result().Body).Decode(&body)

	if body["total"].(float64) != 1 {
		t.Errorf("filtered total: got %v, want 1", body["total"])
	}
}

func TestAPIHistory_ReturnsScanList(t *testing.T) {
	srv, db := testServer(t)

	for _, id := range []string{"scan-h1", "scan-h2", "scan-h3"} {
		_ = db.SaveScan(ScanRecord{ID: id, Timestamp: time.Now().UTC(), Host: "h", Status: "completed"})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	w := httptest.NewRecorder()
	srv.handleAPIHistory(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	scans, ok := body["scans"].([]interface{})
	if !ok {
		t.Fatal("scans field missing or wrong type")
	}
	if len(scans) != 3 {
		t.Errorf("scan count: got %d, want 3", len(scans))
	}
}

func TestAPITrend_ReturnsJSON(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/trend?days=7", nil)
	w := httptest.NewRecorder()
	srv.handleAPITrend(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["trend"]; !ok {
		t.Error("response missing 'trend' field")
	}
	if body["days"].(float64) != 7 {
		t.Errorf("days: got %v, want 7", body["days"])
	}
}

func TestAPIScanners_ReturnsJSON(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scanners", nil)
	w := httptest.NewRecorder()
	srv.handleAPIScanners(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["scanners"]; !ok {
		t.Error("response missing 'scanners' field")
	}
}

func TestAPINotificationRead_MethodNotAllowed(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/read/1", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotificationRead(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Result().StatusCode)
	}
}

func TestAPINotificationRead_BadID(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/notifications/read/abc", nil)
	w := httptest.NewRecorder()
	srv.handleAPINotificationRead(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestHomePage_Returns200(t *testing.T) {
	srv, _ := testServer(t)

	rec := httptest.NewServer(srv.mux)
	defer rec.Close()

	resp, err := http.Get(rec.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// TestDashboardIntegration starts the server on a random port via httptest,
// GETs /, and verifies that the response is a proper 200 HTML page containing
// the "defense-kit" branding text.
func TestDashboardIntegration(t *testing.T) {
	srv, _ := testServer(t)

	ts := httptest.NewServer(srv.mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type: got %q, want text/html", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "defense-kit") {
		t.Errorf("response body does not contain \"defense-kit\"\nbody (first 500 bytes): %s",
			bodyStr[:min(500, len(bodyStr))])
	}
}

