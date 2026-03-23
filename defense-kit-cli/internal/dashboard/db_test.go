package dashboard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func tempDB(t *testing.T) (*DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestOpenDB_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.db")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB returned error: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}
}

func TestMigrate_CreatesTables(t *testing.T) {
	db, _ := tempDB(t)

	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Verify expected tables exist by querying sqlite_master.
	tables := []string{"scans", "findings", "notifications"}
	for _, tbl := range tables {
		var name string
		err := db.db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found after Migrate: %v", tbl, err)
		}
	}
}

func TestSaveScan_And_GetScan(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	want := ScanRecord{
		ID:        "scan-001",
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Host:      "testhost",
		Duration:  1234,
		Total:     5,
		Critical:  1,
		High:      2,
		Medium:    1,
		Low:       1,
		Status:    "completed",
	}

	if err := db.SaveScan(want); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	got, err := db.GetScan("scan-001")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}

	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
	if got.Host != want.Host {
		t.Errorf("Host: got %q, want %q", got.Host, want.Host)
	}
	if got.Total != want.Total {
		t.Errorf("Total: got %d, want %d", got.Total, want.Total)
	}
	if got.Critical != want.Critical {
		t.Errorf("Critical: got %d, want %d", got.Critical, want.Critical)
	}
	if got.Status != want.Status {
		t.Errorf("Status: got %q, want %q", got.Status, want.Status)
	}
}

func TestSaveFindings_And_GetFindings(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	scan := ScanRecord{
		ID:        "scan-002",
		Timestamp: time.Now().UTC(),
		Host:      "testhost",
		Status:    "completed",
	}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}

	want := []scanner.Finding{
		{
			ID:          "f-001",
			Scanner:     "test-scanner",
			Severity:    scanner.SevCritical,
			Title:       "Critical issue",
			Detail:      "Some detail",
			Evidence:    "evidence here",
			Location:    "/etc/test",
			Remediation: "Fix it",
			CanAutoFix:  false,
		},
		{
			ID:       "f-002",
			Scanner:  "test-scanner",
			Severity: scanner.SevLow,
			Title:    "Low issue",
		},
	}

	if err := db.SaveFindings("scan-002", want); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	got, err := db.GetFindings("scan-002")
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("GetFindings returned %d findings, want %d", len(got), len(want))
	}

	// Results are ordered by severity DESC so Critical comes first.
	if got[0].ID != "f-001" {
		t.Errorf("first finding ID: got %q, want %q", got[0].ID, "f-001")
	}
	if got[0].Severity != scanner.SevCritical {
		t.Errorf("first finding severity: got %v, want CRITICAL", got[0].Severity)
	}
}

func TestGetAllFindings_Paginated(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	scan := ScanRecord{ID: "scan-003", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}

	findings := make([]scanner.Finding, 10)
	for i := range findings {
		findings[i] = scanner.Finding{
			ID:       "f-" + string(rune('a'+i)),
			Scanner:  "s",
			Severity: scanner.SevLow,
			Title:    "finding",
		}
	}
	if err := db.SaveFindings("scan-003", findings); err != nil {
		t.Fatal(err)
	}

	got, total, err := db.GetAllFindings(-1, "", 3, 0)
	if err != nil {
		t.Fatalf("GetAllFindings: %v", err)
	}
	if total != 10 {
		t.Errorf("total: got %d, want 10", total)
	}
	if len(got) != 3 {
		t.Errorf("page size: got %d, want 3", len(got))
	}
}

func TestGetLatestScanID(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	// No scans yet — should return empty string without error.
	id, err := db.GetLatestScanID()
	if err != nil {
		t.Fatalf("GetLatestScanID on empty db: %v", err)
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}

	_ = db.SaveScan(ScanRecord{ID: "scan-a", Timestamp: time.Now().UTC().Add(-time.Hour), Host: "h", Status: "completed"})
	_ = db.SaveScan(ScanRecord{ID: "scan-b", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"})

	id, err = db.GetLatestScanID()
	if err != nil {
		t.Fatalf("GetLatestScanID: %v", err)
	}
	if id != "scan-b" {
		t.Errorf("latest scan id: got %q, want %q", id, "scan-b")
	}
}

func TestGetTrend(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	scan := ScanRecord{ID: "scan-trend", Timestamp: time.Now().UTC(), Host: "h", Status: "completed"}
	if err := db.SaveScan(scan); err != nil {
		t.Fatal(err)
	}

	findings := []scanner.Finding{
		{ID: "tf-1", Scanner: "s", Severity: scanner.SevCritical, Title: "c"},
		{ID: "tf-2", Scanner: "s", Severity: scanner.SevHigh, Title: "h"},
	}
	if err := db.SaveFindings("scan-trend", findings); err != nil {
		t.Fatal(err)
	}

	trend, err := db.GetTrend(7)
	if err != nil {
		t.Fatalf("GetTrend: %v", err)
	}

	// Should have at least one day entry.
	if len(trend) == 0 {
		t.Fatal("GetTrend returned no points")
	}

	// Find today's entry.
	today := time.Now().UTC().Format("2006-01-02")
	var todayPoint *TrendPoint
	for i := range trend {
		if trend[i].Date == today {
			todayPoint = &trend[i]
			break
		}
	}
	if todayPoint == nil {
		t.Fatalf("no trend point for today (%s); got: %+v", today, trend)
	}
	if todayPoint.Critical != 1 {
		t.Errorf("today critical: got %d, want 1", todayPoint.Critical)
	}
	if todayPoint.High != 1 {
		t.Errorf("today high: got %d, want 1", todayPoint.High)
	}
}

func TestNotifications(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	n1 := Notification{
		Timestamp: time.Now().UTC(),
		Type:      "scan_complete",
		Severity:  int(scanner.SevCritical),
		Title:     "Test notification",
		Body:      "Body text",
	}
	if err := db.AddNotification(n1); err != nil {
		t.Fatalf("AddNotification: %v", err)
	}

	all, err := db.GetNotifications(false)
	if err != nil {
		t.Fatalf("GetNotifications(all): %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(all))
	}
	if all[0].Title != n1.Title {
		t.Errorf("Title: got %q, want %q", all[0].Title, n1.Title)
	}
	if all[0].Read {
		t.Error("notification should not be read yet")
	}

	// Mark read.
	if err := db.MarkNotificationRead(all[0].ID); err != nil {
		t.Fatalf("MarkNotificationRead: %v", err)
	}

	unread, err := db.GetNotifications(true)
	if err != nil {
		t.Fatalf("GetNotifications(unread): %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("expected 0 unread notifications, got %d", len(unread))
	}
}
