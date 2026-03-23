# Remaining Work — 15 Tasks

**Date:** 2026-03-24
**Current version:** v2.5.0
**Status:** Core scanning complete, production polish remaining

## Summary

67 total tasks planned. 52 done. 15 remaining across 3 categories.

## Dashboard (Phase 9B-D) — 3 tasks

| # | Task | Effort | What It Adds |
|---|------|--------|-------------|
| 1 | Phase 9B: Interactive features | Medium | Trigger scan/harden from UI, baseline management, schedule management |
| 2 | Phase 9C: Background scanner + notifications | Medium | Auto-scan goroutine, bell icon notifications, wired trend charts |
| 3 | Phase 9D: Settings + export | Small | Settings page, CSV/PDF export, dark/light toggle |

## Testing Infrastructure — 5 tasks

| # | Task | Effort | What It Adds |
|---|------|--------|-------------|
| 4 | Vulnerable test container | Medium | Docker container with planted vulns for integration testing |
| 5 | False positive test suite | Medium | Run on clean Ubuntu, suppress known-good patterns |
| 6 | Evasion test suite | Medium | Test bypasses for each detection pattern |
| 7 | CLI integration tests | Medium | Test all commands end-to-end |
| 8 | Performance benchmarks | Small | Per-scanner timing, memory usage |

## Architecture Polish — 7 tasks

| # | Task | Effort | What It Adds |
|---|------|--------|-------------|
| 9 | Structured logging | Small | zerolog/slog with levels, log file |
| 10 | Privilege escalation logic | Medium | Run unprivileged first, batch sudo prompt |
| 11 | Progress reporting | Small | Real-time `[5/38] Scanning: rootkit...` output |
| 12 | Signal handling | Small | Graceful Ctrl+C, save partial results |
| 13 | Output cleanup/rotation | Small | `defense-kit outputs clean --keep 10` |
| 14 | Config validation | Small | Error on invalid config, warn on typos |
| 15 | Scan profiles | Small | `--profile workstation/server/ci` presets |

## Effort Estimate

| Category | Tasks | Estimated Sessions |
|----------|-------|-------------------|
| Dashboard 9B-D | 3 | 2-3 |
| Testing | 5 | 2-3 |
| Architecture | 7 | 2-3 |
| **Total** | **15** | **6-9** |
