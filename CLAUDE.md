# defense-kit

Defensive security toolkit for Claude Code.

## v2 Architecture (Hybrid)

- **Go binary on HOST** — OS, kernel, process, network, and SSH scans (requires real system access)
- **Docker container** — isolated code, dependency, container, and secret scanning

## Setup

```bash
# Build Go binary and Docker image
make docker-build

# Start container (set TARGET_PATH to the code you want to scan)
TARGET_PATH=/path/to/code make docker-up

# Open a shell in the container
docker compose -f docker/docker-compose.yml exec defense-kit bash
```

## Usage

- `/defense-kit scan` — audit everything (read-only)
- `/defense-kit harden` — fix issues with approval
- `/defense-kit monitor` — watch for changes
- `/defense-kit comply` — compliance report

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build Go binary |
| `make docker-build` | Build Go binary then Docker image |
| `make docker-up` | Start container (requires TARGET_PATH) |
| `make docker-scan` | Run scan inside running container |
| `make docker-down` | Stop container |

## Rules

- Scan mode is READ-ONLY
- Harden mode REQUIRES user approval for every change
- Always generate rollback script before modifying
- Never break SSH or networking
