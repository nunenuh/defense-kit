# defense-kit

Defensive security toolkit for Claude Code.

## Setup

```bash
docker compose build
TARGET_PATH=/path/to/code docker compose up -d
docker compose exec defense-kit bash
```

## Usage

- `/defense-kit scan` — audit everything (read-only)
- `/defense-kit harden` — fix issues with approval
- `/defense-kit monitor` — watch for changes
- `/defense-kit comply` — compliance report

## Rules

- Scan mode is READ-ONLY
- Harden mode REQUIRES user approval for every change
- Always generate rollback script before modifying
- Never break SSH or networking
