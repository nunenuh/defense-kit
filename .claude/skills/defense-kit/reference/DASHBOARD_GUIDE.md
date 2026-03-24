# Dashboard Guide

## Start

```bash
defense-kit dashboard --port 8080 --open
```

Binds to 127.0.0.1 only (localhost). No network exposure.

## Pages

| Page | URL | What It Shows |
|------|-----|--------------|
| Overview | `/` | Severity cards, recent findings, scan button |
| Findings | `/findings` | Filterable findings table with details |
| History | `/history` | Scan timeline, trend chart |
| Scanners | `/scanners` | Scanner + tool availability |
| Settings | `/settings` | Config editor |

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/status` | Current status + summary |
| GET | `/api/findings` | Paginated findings (?severity=&scanner=&limit=&offset=) |
| GET | `/api/history` | Scan list |
| GET | `/api/trend?days=30` | Daily severity counts for chart |
| GET | `/api/scanners` | Scanner + tool status |
| POST | `/api/scan` | Trigger scan |
| GET | `/api/scan/status/{id}` | Poll scan progress |
| POST | `/api/harden/preview` | Preview fixable findings |
| POST | `/api/baseline/update` | Set current as baseline |
| GET | `/api/baseline/status` | Baseline info |
| POST | `/api/schedule/enable` | Enable auto-scan |
| POST | `/api/schedule/disable` | Disable auto-scan |
| GET | `/api/schedule/status` | Schedule info |
| GET | `/api/notifications` | Unread notifications |
| GET | `/api/notifications/count` | Unread count |
| GET | `/api/settings` | Current config |
| POST | `/api/settings` | Update config |
| GET | `/api/export/{scan_id}?format=csv` | Download findings as CSV |

## Database

SQLite at `~/.defense-kit/dashboard.db`. Tables: scans, findings, notifications, baselines, schedule_config.
