# Output Structure

## Data Directories

```
~/.defense-kit/
├── outputs/
│   └── dk-{YYYYMMDD-HHMMSS}/
│       └── findings.json         # Scan results
├── baseline.json                 # Current baseline
├── dashboard.db                  # SQLite (dashboard)
└── rollback-{timestamp}.sh      # Hardener rollback scripts

~/.config/defense-kit/
└── config.yml                    # Configuration
```

## findings.json Schema

```json
{
  "scan_id": "dk-20260324-143022",
  "host": "hostname",
  "time": "2026-03-24T14:30:22Z",
  "summary": {"critical": 2, "high": 5, "medium": 18, "low": 22, "total": 47},
  "findings": [
    {
      "id": "rootkit-a3f8c2e91b04",
      "scanner": "rootkit",
      "severity": 3,
      "title": "Hidden kernel module",
      "detail": "...",
      "evidence": "...",
      "location": "/proc/modules",
      "remediation": "...",
      "can_auto_fix": false,
      "references": [],
      "metadata": {}
    }
  ],
  "results": [
    {"scanner": "rootkit", "status": 0, "findings": [...], "duration": 1200000000}
  ]
}
```

## Severity Values

| Value | Label | Color |
|-------|-------|-------|
| 0 | LOW | cyan |
| 1 | MEDIUM | yellow |
| 2 | HIGH | orange |
| 3 | CRITICAL | red |

## Scan Status Values

| Value | Label |
|-------|-------|
| 0 | success |
| 1 | partial |
| 2 | failed |
| 3 | skipped |
