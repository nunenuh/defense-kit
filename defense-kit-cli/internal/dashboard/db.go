package dashboard

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ScanRecord holds summary information about a completed scan.
type ScanRecord struct {
	ID        string
	Timestamp time.Time
	Host      string
	Duration  int
	Total     int
	Critical  int
	High      int
	Medium    int
	Low       int
	Status    string
}

// TrendPoint holds daily severity counts for trend charts.
type TrendPoint struct {
	Date     string // YYYY-MM-DD
	Critical int
	High     int
	Medium   int
	Low      int
}

// Notification represents a dashboard notification entry.
type Notification struct {
	ID        int
	Timestamp time.Time
	Type      string
	Severity  int
	Title     string
	Body      string
	Read      bool
}

// DB wraps a SQLite database connection with helper methods.
type DB struct {
	db *sql.DB
}

// OpenDB opens (or creates) a SQLite database at the given path.
// The parent directory is created automatically if it does not exist.
func OpenDB(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode and foreign keys.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}

	return &DB{db: sqlDB}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// Migrate creates all required tables and indexes if they do not already exist.
func (d *DB) Migrate() error {
	ddl := `
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    host TEXT NOT NULL,
    duration_ms INTEGER,
    total INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    scanner TEXT NOT NULL,
    severity INTEGER NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    location TEXT,
    remediation TEXT,
    can_auto_fix BOOLEAN DEFAULT FALSE,
    first_seen DATETIME,
    PRIMARY KEY (id, scan_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    type TEXT,
    severity INTEGER,
    title TEXT,
    body TEXT,
    read BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    finding_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schedule_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN DEFAULT FALSE,
    interval TEXT DEFAULT '6h',
    mode TEXT DEFAULT 'quick',
    updated_at DATETIME NOT NULL
);
`
	_, err := d.db.Exec(ddl)
	return err
}

// SaveScan inserts or replaces a scan summary record.
func (d *DB) SaveScan(scan ScanRecord) error {
	const q = `
INSERT OR REPLACE INTO scans
    (id, timestamp, host, duration_ms, total, critical, high, medium, low, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(q,
		scan.ID,
		scan.Timestamp.UTC().Format(time.RFC3339),
		scan.Host,
		scan.Duration,
		scan.Total,
		scan.Critical,
		scan.High,
		scan.Medium,
		scan.Low,
		scan.Status,
	)
	return err
}

// SaveFindings bulk-inserts findings for a given scan.
// Existing rows for the same (id, scan_id) are replaced.
func (d *DB) SaveFindings(scanID string, findings []scanner.Finding) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	const q = `
INSERT OR REPLACE INTO findings
    (id, scan_id, scanner, severity, title, detail, evidence,
     location, remediation, can_auto_fix, first_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		if _, err := tx.Exec(q,
			f.ID, scanID, f.Scanner, int(f.Severity),
			f.Title, f.Detail, f.Evidence,
			f.Location, f.Remediation, f.CanAutoFix,
			now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetScans returns the most-recent `limit` scans, newest first.
// Pass 0 for limit to return all scans.
func (d *DB) GetScans(limit int) ([]ScanRecord, error) {
	q := `
SELECT id, timestamp, host, duration_ms, total, critical, high, medium, low, status
FROM scans
ORDER BY timestamp DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanRows(rows)
}

// GetScan returns a single scan by its ID.
func (d *DB) GetScan(id string) (ScanRecord, error) {
	const q = `
SELECT id, timestamp, host, duration_ms, total, critical, high, medium, low, status
FROM scans WHERE id = ?`

	rows, err := d.db.Query(q, id)
	if err != nil {
		return ScanRecord{}, err
	}
	defer rows.Close()

	records, err := scanRows(rows)
	if err != nil {
		return ScanRecord{}, err
	}
	if len(records) == 0 {
		return ScanRecord{}, fmt.Errorf("scan %q not found", id)
	}
	return records[0], nil
}

// scanRows decodes query rows into ScanRecord values.
func scanRows(rows *sql.Rows) ([]ScanRecord, error) {
	var out []ScanRecord
	for rows.Next() {
		var r ScanRecord
		var ts string
		if err := rows.Scan(
			&r.ID, &ts, &r.Host, &r.Duration,
			&r.Total, &r.Critical, &r.High, &r.Medium, &r.Low,
			&r.Status,
		); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, ts)
		r.Timestamp = t
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetFindings returns all findings for a specific scan.
func (d *DB) GetFindings(scanID string) ([]scanner.Finding, error) {
	const q = `
SELECT id, scanner, severity, title, detail, evidence, location, remediation, can_auto_fix
FROM findings WHERE scan_id = ?
ORDER BY severity DESC`

	rows, err := d.db.Query(q, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return findingRows(rows)
}

// GetAllFindings returns a paginated, optionally-filtered list of findings
// and the total count matching the filter.
// severity=-1 means "all severities"; scannerName="" means "all scanners".
func (d *DB) GetAllFindings(severity int, scannerName string, limit, offset int) ([]scanner.Finding, int, error) {
	whereClause, args := buildFindingFilter(severity, scannerName)

	countQ := "SELECT COUNT(*) FROM findings" + whereClause
	var total int
	if err := d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQ := `
SELECT id, scanner, severity, title, detail, evidence, location, remediation, can_auto_fix
FROM findings` + whereClause + ` ORDER BY severity DESC`

	if limit > 0 {
		listArgs := make([]interface{}, len(args))
		copy(listArgs, args)
		listQ += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
		args = listArgs
	}

	rows, err := d.db.Query(listQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	findings, err := findingRows(rows)
	return findings, total, err
}

// buildFindingFilter constructs a WHERE clause and argument list for finding queries.
func buildFindingFilter(severity int, scannerName string) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if severity >= 0 {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}
	if scannerName != "" {
		conditions = append(conditions, "scanner = ?")
		args = append(args, scannerName)
	}

	if len(conditions) == 0 {
		return "", nil
	}

	clause := " WHERE " + conditions[0]
	for _, c := range conditions[1:] {
		clause += " AND " + c
	}
	return clause, args
}

// findingRows decodes query rows into scanner.Finding values.
func findingRows(rows *sql.Rows) ([]scanner.Finding, error) {
	var out []scanner.Finding
	for rows.Next() {
		var f scanner.Finding
		var sev int
		if err := rows.Scan(
			&f.ID, &f.Scanner, &sev,
			&f.Title, &f.Detail, &f.Evidence,
			&f.Location, &f.Remediation, &f.CanAutoFix,
		); err != nil {
			return nil, err
		}
		f.Severity = scanner.Severity(sev)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetLatestScanID returns the ID of the most-recent scan, or an empty string
// when no scans exist yet.
func (d *DB) GetLatestScanID() (string, error) {
	const q = `SELECT id FROM scans ORDER BY timestamp DESC LIMIT 1`
	var id string
	err := d.db.QueryRow(q).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// GetTrend returns daily severity counts for the last `days` calendar days.
func (d *DB) GetTrend(days int) ([]TrendPoint, error) {
	const q = `
SELECT
    date(f.first_seen) AS day,
    SUM(CASE WHEN f.severity = 3 THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 2 THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN f.severity = 1 THEN 1 ELSE 0 END) AS medium,
    SUM(CASE WHEN f.severity = 0 THEN 1 ELSE 0 END) AS low
FROM findings f
JOIN scans s ON s.id = f.scan_id
WHERE f.first_seen >= date('now', ?)
GROUP BY day
ORDER BY day ASC`

	daysParam := fmt.Sprintf("-%d days", days)
	rows, err := d.db.Query(q, daysParam)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TrendPoint
	for rows.Next() {
		var tp TrendPoint
		if err := rows.Scan(&tp.Date, &tp.Critical, &tp.High, &tp.Medium, &tp.Low); err != nil {
			return nil, err
		}
		out = append(out, tp)
	}
	return out, rows.Err()
}

// AddNotification inserts a new notification.
func (d *DB) AddNotification(n Notification) error {
	const q = `
INSERT INTO notifications (timestamp, type, severity, title, body, read)
VALUES (?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(q,
		n.Timestamp.UTC().Format(time.RFC3339),
		n.Type, n.Severity, n.Title, n.Body, n.Read,
	)
	return err
}

// GetNotifications returns all notifications, optionally limited to unread ones.
func (d *DB) GetNotifications(unreadOnly bool) ([]Notification, error) {
	q := `
SELECT id, timestamp, type, severity, title, body, read
FROM notifications`
	if unreadOnly {
		q += " WHERE read = FALSE"
	}
	q += " ORDER BY timestamp DESC"

	rows, err := d.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Notification
	for rows.Next() {
		var n Notification
		var ts string
		var readVal int
		if err := rows.Scan(&n.ID, &ts, &n.Type, &n.Severity, &n.Title, &n.Body, &readVal); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, ts)
		n.Timestamp = t
		n.Read = readVal != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkNotificationRead marks a single notification as read.
func (d *DB) MarkNotificationRead(id int) error {
	const q = `UPDATE notifications SET read = TRUE WHERE id = ?`
	_, err := d.db.Exec(q, id)
	return err
}

// BaselineRecord holds info about the saved baseline scan.
type BaselineRecord struct {
	ID           int
	ScanID       string
	CreatedAt    time.Time
	FindingCount int
}

// SaveBaseline inserts a new baseline record, replacing any previous one.
func (d *DB) SaveBaseline(scanID string, findingCount int) error {
	const q = `
INSERT OR REPLACE INTO baselines (id, scan_id, created_at, finding_count)
VALUES (1, ?, ?, ?)`
	_, err := d.db.Exec(q, scanID, time.Now().UTC().Format(time.RFC3339), findingCount)
	return err
}

// GetBaseline returns the current baseline record, if any.
// Returns nil (no error) when no baseline has been set.
func (d *DB) GetBaseline() (*BaselineRecord, error) {
	const q = `SELECT id, scan_id, created_at, finding_count FROM baselines WHERE id = 1`
	var b BaselineRecord
	var ts string
	err := d.db.QueryRow(q).Scan(&b.ID, &b.ScanID, &ts, &b.FindingCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339, ts)
	b.CreatedAt = t
	return &b, nil
}

// ScheduleConfig holds the persisted schedule configuration.
type ScheduleConfig struct {
	Enabled   bool
	Interval  string
	Mode      string
	UpdatedAt time.Time
}

// SaveScheduleConfig upserts the singleton schedule configuration row.
func (d *DB) SaveScheduleConfig(cfg ScheduleConfig) error {
	const q = `
INSERT OR REPLACE INTO schedule_config (id, enabled, interval, mode, updated_at)
VALUES (1, ?, ?, ?, ?)`
	_, err := d.db.Exec(q, cfg.Enabled, cfg.Interval, cfg.Mode,
		cfg.UpdatedAt.UTC().Format(time.RFC3339))
	return err
}

// GetScheduleConfig returns the current schedule configuration.
// Returns a default (disabled) config when none has been saved.
func (d *DB) GetScheduleConfig() (ScheduleConfig, error) {
	const q = `SELECT enabled, interval, mode, updated_at FROM schedule_config WHERE id = 1`
	var cfg ScheduleConfig
	var ts string
	var enabledInt int
	err := d.db.QueryRow(q).Scan(&enabledInt, &cfg.Interval, &cfg.Mode, &ts)
	if err == sql.ErrNoRows {
		return ScheduleConfig{Enabled: false, Interval: "6h", Mode: "quick"}, nil
	}
	if err != nil {
		return ScheduleConfig{}, err
	}
	cfg.Enabled = enabledInt != 0
	t, _ := time.Parse(time.RFC3339, ts)
	cfg.UpdatedAt = t
	return cfg, nil
}
