# Contributing to defense-kit

## Setup

```bash
git clone https://github.com/nunenuh/defense-kit.git
cd defense-kit/defense-kit-cli
make build
make test
```

Requires Go 1.22+.

## Adding a Scanner

1. Create file in `internal/scanner/{group}/` (e.g., `internal/scanner/system/newscanner.go`)
2. Implement `scanner.Scanner` interface:
   ```go
   type MyScanner struct{}
   func (s *MyScanner) Name() string { return "my_scanner" }
   func (s *MyScanner) Category() string { return "system" }
   func (s *MyScanner) Description() string { return "..." }
   func (s *MyScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) { ... }
   func (s *MyScanner) RequiredTools() []string { return nil }
   func (s *MyScanner) OptionalTools() []string { return nil }
   func (s *MyScanner) RequiresRoot() bool { return false }
   func (s *MyScanner) Available() bool { return true }
   ```
3. Register in `cmd/defense-kit/register.go`
4. Add tests
5. Update `.claude/skills/defense-kit/reference/SCAN_INDEX.md`

## Adding a Hardener

1. Create file in `internal/hardener/` (e.g., `internal/hardener/newfix.go`)
2. Implement `hardener.Hardener` interface
3. Register in `cmd/defense-kit/main.go` `runHarden` function

## Branching

- `dev` — active development
- `main` — stable releases
- Feature branches from `dev`, PRs to `dev`
- Releases: merge `dev` → `main`, tag `v0.x.y`

## Commits

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

## Code Style

```bash
go vet ./...
go fmt ./...
go test ./... -race
```

## Testing

- Write tests first (TDD)
- Target 80%+ coverage
- Use `-race` flag
- For scanners needing root: add injectable constructor (e.g., `NewScannerWithPath`)
