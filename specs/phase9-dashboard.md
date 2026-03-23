# Phase 9: Local Security Dashboard

**Date:** 2026-03-23
**Status:** Draft
**Priority:** HIGH — makes defense-kit usable as a daily security tool

---

## 1. Problem

Defense-kit produces findings via CLI but there's no persistent view of your security posture. You have to run commands, read terminal output, and mentally track what changed. There's no way to:
- See historical trends (am I getting more secure over time?)
- Get notified of new findings without running a command
- Manage hardening from a visual interface
- Understand your overall security posture at a glance

## 2. Goal

Single command — `defense-kit dashboard` — opens a local web UI at `http://localhost:8080` that shows everything about your system's security state. Zero external dependencies. Works offline. ~20MB RAM.

## 3. Non-Goals

- Not a multi-host SIEM (that's Wazuh territory)
- Not a cloud service
- No user authentication (localhost only, single user)
- No React/Vue/Angular — minimal JS only

## 4. Architecture

```
defense-kit dashboard --port 8080
    │
    ├── HTTP server (Go net/http)
    │   ├── GET /                    → Dashboard home
    │   ├── GET /findings            → Current findings list
    │   ├── GET /history             → Scan history + trends
    │   ├── GET /scanners            → Scanner + tool status
    │   ├── GET /schedule            → Schedule management
    │   ├── GET /settings            → Alert + config settings
    │   ├── POST /api/scan           → Trigger scan
    │   ├── POST /api/harden         → Trigger harden (dry-run first)
    │   ├── GET /api/findings        → JSON findings data
    │   ├── GET /api/history         → JSON scan history
    │   └── GET /api/status          → JSON current status
    │
    ├── SQLite database (~/.defense-kit/dashboard.db)
    │   ├── scans table              → scan_id, timestamp, host, duration
    │   ├── findings table           → finding_id, scan_id, severity, scanner, title, ...
    │   ├── baselines table          → baseline snapshots
    │   └── alerts table             → alert history
    │
    ├── Background scanner (goroutine)
    │   ├── Runs on configurable interval (default: 6h)
    │   ├── Saves results to SQLite
    │   ├── Computes diff against last scan
    │   └── Triggers alerts for new findings
    │
    └── Embedded static files (go:embed)
        ├── HTML templates
        ├── CSS (dark theme, same as HTML reporter)
        └── JS (htmx for interactivity, Chart.js for graphs)
```

### Why SQLite

- Zero config — single file at `~/.defense-kit/dashboard.db`
- No server process — embedded in Go via `modernc.org/sqlite` (pure Go, no CGO)
- Fast enough for single-user: 1000s of findings, dozens of scans
- Easy to backup: copy one file
- Easy to query: `sqlite3 dashboard.db "SELECT ..."`

### Why htmx + Chart.js

- htmx: server-rendered HTML with dynamic updates, no build step, ~14KB
- Chart.js: one chart library for trend graphs, ~60KB
- Both loaded from embedded files (no CDN, works offline)
- Total JS: <100KB

## 5. Database Schema

```sql
CREATE TABLE scans (
    id          TEXT PRIMARY KEY,   -- dk-20260321-143022
    timestamp   DATETIME NOT NULL,
    host        TEXT NOT NULL,
    duration_ms INTEGER,
    total       INTEGER DEFAULT 0,
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    status      TEXT DEFAULT 'completed'  -- completed, interrupted, failed
);

CREATE TABLE findings (
    id          TEXT NOT NULL,      -- finding ID (deterministic)
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    scanner     TEXT NOT NULL,
    severity    INTEGER NOT NULL,   -- 0=low, 1=medium, 2=high, 3=critical
    title       TEXT NOT NULL,
    detail      TEXT,
    evidence    TEXT,
    location    TEXT,
    remediation TEXT,
    can_auto_fix BOOLEAN DEFAULT FALSE,
    first_seen  DATETIME,          -- first scan that found this
    PRIMARY KEY (id, scan_id)
);

CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME NOT NULL,
    finding_id  TEXT,
    channel     TEXT,              -- slack, email, webhook, dashboard
    severity    INTEGER,
    title       TEXT,
    delivered   BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_scanner ON findings(scanner);
CREATE INDEX idx_findings_first_seen ON findings(first_seen);
```

## 6. Dashboard Pages

### 6.1 Home — Security Overview

```
┌─────────────────────────────────────────────────────────┐
│  defense-kit — erfan-laptop                    ● Online │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐               │
│  │  3   │  │  12  │  │  28  │  │  45  │               │
│  │ CRIT │  │ HIGH │  │ MED  │  │ LOW  │               │
│  └──────┘  └──────┘  └──────┘  └──────┘               │
│                                                         │
│  Last scan: 2h ago (dk-20260323-141500)                │
│  Next scan: in 4h (scheduled every 6h)                 │
│  Baseline: 2 new findings since last update            │
│                                                         │
│  ┌─── 30-Day Trend ────────────────────────────┐       │
│  │  ▓▓▓▓░░░░░░  Critical                       │       │
│  │  ▓▓▓▓▓▓░░░░  High                           │       │
│  │  ▓▓▓▓▓▓▓▓░░  Medium                         │       │
│  │  ▓▓▓▓▓▓▓▓▓▓  Low                            │       │
│  └──────────────────────────────────────────────┘       │
│                                                         │
│  [Scan Now]  [Harden]  [Update Baseline]               │
│                                                         │
│  Recent Changes:                                        │
│  🔴 NEW: Reverse shell detected (PID 4821)    2h ago   │
│  🟢 RESOLVED: PermitRootLogin fixed           1d ago   │
│  🟡 CHANGED: CVE-2024-1234 HIGH→CRITICAL     3d ago   │
└─────────────────────────────────────────────────────────┘
```

### 6.2 Findings — Detailed Finding List

```
┌─────────────────────────────────────────────────────────┐
│  Findings (88 total)                                    │
│  Filter: [All▾] [All Scanners▾] [Search...]            │
├─────────────────────────────────────────────────────────┤
│  ■ CRITICAL  Reverse shell on port 4444                │
│    Scanner: processes  Location: PID 4821              │
│    First seen: 2h ago  Evidence: bash -i >& /dev/tcp.. │
│    [Fix] [Acknowledge] [Details]                       │
│  ──────────────────────────────────────────────────     │
│  ■ CRITICAL  AWS access key in .bash_history           │
│    Scanner: credentials  Location: /home/erfan/...     │
│    First seen: 5d ago  Evidence: AKIA...               │
│    [Details]                                            │
│  ──────────────────────────────────────────────────     │
│  ■ HIGH  PermitRootLogin enabled                       │
│    Scanner: ssh  Location: /etc/ssh/sshd_config        │
│    First seen: 30d ago  Can auto-fix: YES              │
│    [Fix] [Acknowledge] [Details]                       │
└─────────────────────────────────────────────────────────┘
```

### 6.3 History — Scan Timeline

```
┌─────────────────────────────────────────────────────────┐
│  Scan History                                           │
│  ┌─── Severity Over Time (Chart.js line chart) ──────┐ │
│  │                                    ╱               │ │
│  │  Critical ──────────────────────╱──                │ │
│  │  High     ─────────╲──────────╱────                │ │
│  │  Medium   ──────────────────────────               │ │
│  │  Low      ──────────────────────────               │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  Scan Log:                                              │
│  dk-20260323-141500  88 findings  45s  [View] [Diff]   │
│  dk-20260323-081500  86 findings  42s  [View] [Diff]   │
│  dk-20260322-201500  86 findings  44s  [View] [Diff]   │
│  dk-20260322-141500  90 findings  43s  [View] [Diff]   │
└─────────────────────────────────────────────────────────┘
```

### 6.4 Scanners — Tool Status

```
┌─────────────────────────────────────────────────────────┐
│  Scanner Status (31 scanners, 29 available)             │
├─────────────────────────────────────────────────────────┤
│  environment  ████████████  4/4  shell_rc ✓ env_vars ✓ │
│  persistence  ████████░░░░  2/3  cron ✓ systemd ⬜     │
│  process      ████████░░░░  2/3  processes ✓ memory ⬜  │
│  ...                                                    │
│                                                         │
│  External Tools (8/17 installed)                        │
│  ✓ rkhunter 1.4.6  ✓ chkrootkit 0.55  ✓ lynis 3.0.7  │
│  ✓ ClamAV 1.4.3   ✗ gitleaks         ✗ trivy          │
│  ✓ nmap 7.80       ✓ aide 0.17.4     ✓ debsums 3.0.2  │
│                                                         │
│  [Install Missing Tools]                                │
└─────────────────────────────────────────────────────────┘
```

### 6.5 Schedule — Monitoring Config

```
┌─────────────────────────────────────────────────────────┐
│  Scheduled Scanning                                     │
├─────────────────────────────────────────────────────────┤
│  Status: ● Enabled (systemd timer)                     │
│  Interval: every 6 hours                                │
│  Mode: quick scan                                       │
│  Last run: 2h ago (dk-20260323-141500)                 │
│  Next run: in 4h                                        │
│                                                         │
│  [Change Interval] [Disable] [Run Now]                 │
│                                                         │
│  Alert Channels:                                        │
│  ✓ Dashboard notifications (always on)                 │
│  ✗ Slack webhook (not configured)                      │
│  ✗ Email (not configured)                              │
│  ✗ Webhook (not configured)                            │
│                                                         │
│  [Configure Alerts]                                     │
└─────────────────────────────────────────────────────────┘
```

### 6.6 Settings

```
┌─────────────────────────────────────────────────────────┐
│  Settings                                               │
├─────────────────────────────────────────────────────────┤
│  Scan Configuration:                                    │
│  Concurrency: [4]  Timeout: [60s]                      │
│  Exclude paths: /proc, /sys, /dev                      │
│                                                         │
│  Alerts:                                                │
│  Slack webhook URL: [________________________]          │
│  Min severity: [HIGH ▾]                                │
│                                                         │
│  Email:                                                 │
│  To: [________________________]                         │
│  SMTP host: [________________________]                  │
│  Min severity: [CRITICAL ▾]                            │
│                                                         │
│  Webhook:                                               │
│  URL: [________________________]                        │
│  HMAC secret: [________________________]                │
│  Min severity: [MEDIUM ▾]                              │
│                                                         │
│  [Save]                                                 │
└─────────────────────────────────────────────────────────┘
```

## 7. API Endpoints

### Read endpoints (GET)

| Endpoint | Response | Purpose |
|----------|----------|---------|
| `/api/status` | `{host, last_scan, next_scan, summary, new_since_baseline}` | Dashboard home data |
| `/api/findings?severity=&scanner=&page=&limit=` | `{findings[], total, page}` | Paginated findings |
| `/api/findings/{id}` | `{finding, history[]}` | Single finding + when it was seen |
| `/api/history?days=30` | `{scans[]}` | Scan history with summary counts |
| `/api/history/{scan_id}` | `{scan, findings[]}` | Single scan details |
| `/api/diff/{scan_id_old}/{scan_id_new}` | `{new[], resolved[], changed[]}` | Diff between scans |
| `/api/scanners` | `{scanners[], tools[]}` | Scanner + tool status |
| `/api/schedule` | `{enabled, backend, interval, last_run, next_run}` | Schedule status |
| `/api/trend?days=30` | `{dates[], critical[], high[], medium[], low[]}` | Trend data for charts |

### Action endpoints (POST)

| Endpoint | Body | Purpose |
|----------|------|---------|
| `/api/scan` | `{category?, quick?}` | Trigger a scan |
| `/api/scan/cancel` | — | Cancel running scan |
| `/api/harden/preview` | — | Dry-run harden, return fixable findings |
| `/api/harden/apply` | `{finding_ids[]}` | Apply specific fixes (with approval) |
| `/api/baseline/update` | — | Set current as baseline |
| `/api/findings/{id}/acknowledge` | — | Acknowledge a finding (suppress alerts) |
| `/api/schedule/enable` | `{interval, mode}` | Enable scheduled scanning |
| `/api/schedule/disable` | — | Disable scheduled scanning |
| `/api/settings` | `{config object}` | Update settings |

## 8. Background Scanner

```go
type BackgroundScanner struct {
    registry  *scanner.Registry
    db        *sqlite.DB
    interval  time.Duration
    stopCh    chan struct{}
}

func (b *BackgroundScanner) Start()  // goroutine: scan on interval
func (b *BackgroundScanner) Stop()
func (b *BackgroundScanner) RunNow() // trigger immediate scan
```

Behavior:
- Runs quick scan on interval (default 6h, configurable)
- Saves results to SQLite
- Computes diff against previous scan
- Creates dashboard notification for new findings
- Sends alerts via configured channels for new HIGH/CRITICAL
- Does NOT interfere with manual scans

## 9. Notification System

Dashboard-native notifications (separate from external alerts):

```go
type Notification struct {
    ID        int
    Timestamp time.Time
    Type      string  // new_finding, resolved, scan_complete, harden_complete
    Severity  int
    Title     string
    Body      string
    Read      bool
}
```

- Bell icon in header with unread count
- Click to see notification list
- Auto-dismiss after 7 days
- Stored in SQLite `notifications` table

## 10. File Map

```
defense-kit-cli/
├── internal/
│   └── dashboard/
│       ├── server.go          # HTTP server, router, middleware
│       ├── handlers.go        # Page handlers (HTML responses)
│       ├── api.go             # API handlers (JSON responses)
│       ├── db.go              # SQLite schema, queries, migrations
│       ├── background.go      # Background scanner goroutine
│       ├── notifications.go   # Dashboard notification system
│       ├── static/            # go:embed static files
│       │   ├── css/
│       │   │   └── dashboard.css
│       │   └── js/
│       │       ├── htmx.min.js
│       │       └── chart.min.js
│       ├── templates/         # go:embed HTML templates
│       │   ├── layout.html    # Base layout with nav
│       │   ├── home.html
│       │   ├── findings.html
│       │   ├── history.html
│       │   ├── scanners.html
│       │   ├── schedule.html
│       │   └── settings.html
│       ├── server_test.go
│       └── db_test.go
└── cmd/defense-kit/
    └── main.go                # Add dashboard command
```

## 11. CLI Command

```
defense-kit dashboard [--port 8080] [--open]
```

- `--port`: HTTP port (default 8080)
- `--open`: auto-open browser
- Binds to `127.0.0.1` only (localhost, no network exposure)
- Prints: `Dashboard running at http://localhost:8080`
- Ctrl+C to stop

## 12. Dependencies

| Dependency | Purpose | Size |
|------------|---------|------|
| `modernc.org/sqlite` | Pure Go SQLite (no CGO) | ~5MB binary increase |
| htmx | Dynamic HTML updates | 14KB (embedded) |
| Chart.js | Trend charts | 60KB (embedded) |

Total binary size increase: ~5MB. No external services required.

## 13. Security Considerations

- Binds to `127.0.0.1` only — not accessible from network
- No authentication (single-user, localhost)
- API endpoints that trigger actions (scan, harden) require POST
- Harden actions still require the approval workflow
- Settings page does not expose secrets (masked in UI)
- SQLite file permissions: 0600 (owner only)
- Evidence in findings is HTML-escaped (XSS prevention)

## 14. Implementation Phases

### Phase 9A: Core Dashboard (MVP)
- SQLite storage (db.go)
- Scan result persistence
- Home page with severity summary
- Findings page with filters
- Scan history page
- API endpoints for data
- `defense-kit dashboard` command

### Phase 9B: Interactive Features
- Trigger scan from UI
- Trigger harden (preview + apply) from UI
- Baseline management from UI
- Schedule management from UI

### Phase 9C: Background + Notifications
- Background scanner goroutine
- Dashboard notifications
- Trend charts (Chart.js)
- Diff view between scans

### Phase 9D: Settings + Polish
- Settings page (alert config, scan config)
- Tool install guidance
- Export findings as CSV/PDF
- Dark/light theme toggle
