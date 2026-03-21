# Defense-Kit v2 Phase 2: External Tool Integration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add external tool discovery, execution, and output parsing so scanners can leverage rkhunter, ClamAV, gitleaks, trivy, ssh-audit, lynis, and other installed tools for deeper detection.

**Architecture:** ToolRunner interface executes external binaries via `exec.CommandContext` (no shell). ToolRegistry discovers installed tools and checks versions. Scanners call ToolRunner when available, fall back to native Go checks when not. Preflight command reports tool availability.

**Tech Stack:** Go 1.22+, exec.CommandContext, JSON output parsing

**Spec:** `docs/superpowers/specs/2026-03-21-defense-kit-v2-design.md` (Sections 5.4, 12, 27, 28)

---

## File Map

```
defense-kit-cli/
├── internal/
│   ├── tools/
│   │   ├── registry.go              # Tool definitions, discovery, version checks
│   │   ├── runner.go                # Execute external tools safely
│   │   ├── parser.go                # Parse tool output (JSON, text) into Findings
│   │   ├── python.go                # Python script executor
│   │   ├── tools_test.go            # Tests for registry + runner
│   │   └── parser_test.go           # Tests for output parsers
│   ├── scanner/
│   │   ├── environment/
│   │   │   └── shellrc.go           # (no external tools needed)
│   │   ├── persistence/
│   │   │   └── cron.go              # (no external tools needed)
│   │   ├── process/
│   │   │   └── suspicious.go        # (no external tools needed)
│   │   ├── filesystem/
│   │   │   └── integrity.go         # + AIDE integration
│   │   ├── network/
│   │   │   └── ports.go             # + nmap integration
│   │   ├── auth/
│   │   │   └── ssh.go               # + ssh-audit integration
│   │   ├── system/
│   │   │   ├── rootkit.go           # + rkhunter/chkrootkit integration
│   │   │   └── packagemgr.go        # + debsums integration (fill stub)
│   │   └── code/
│   │       ├── credentials.go       # + gitleaks/trufflehog integration
│   │       ├── supplychain.go       # + trivy/grype integration (fill stub)
│   │       └── containers.go        # + hadolint/dockle integration (fill stub)
│   └── cmd/defense-kit/
│       └── main.go                  # Update tools check to show versions
├── tools/
│   └── REGISTRY.md                  # External tool catalog (documentation)
└── tools/
    └── PIPELINES.md                 # Scan chain definitions (documentation)
```

---

### Task 1: Tool Registry — Define and Discover External Tools

**Files:**
- Create: `defense-kit-cli/internal/tools/registry.go`
- Create: `defense-kit-cli/internal/tools/tools_test.go`

- [ ] **Step 1: Write failing test for tool definition and discovery**

```go
// internal/tools/tools_test.go
package tools

import (
	"testing"
)

func TestToolDefFields(t *testing.T) {
	td := ToolDef{
		Name:       "rkhunter",
		Binary:     "rkhunter",
		Purpose:    "Rootkit detection",
		Category:   "system",
		MinVersion: "1.4.6",
		VersionCmd: []string{"rkhunter", "--version"},
		VersionRe:  `Rootkit Hunter (\d+\.\d+\.\d+)`,
	}
	if td.Name != "rkhunter" {
		t.Errorf("name = %s", td.Name)
	}
}

func TestRegistryLookup(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "rkhunter", Binary: "rkhunter", Category: "system"})
	r.Add(ToolDef{Name: "gitleaks", Binary: "gitleaks", Category: "secrets"})

	td, ok := r.Get("rkhunter")
	if !ok {
		t.Fatal("rkhunter should be registered")
	}
	if td.Category != "system" {
		t.Errorf("category = %s", td.Category)
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Fatal("should not find nonexistent tool")
	}

	all := r.All()
	if len(all) != 2 {
		t.Errorf("all = %d, want 2", len(all))
	}
}

func TestRegistryByCategory(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "rkhunter", Binary: "rkhunter", Category: "system"})
	r.Add(ToolDef{Name: "chkrootkit", Binary: "chkrootkit", Category: "system"})
	r.Add(ToolDef{Name: "gitleaks", Binary: "gitleaks", Category: "secrets"})

	sys := r.ByCategory("system")
	if len(sys) != 2 {
		t.Errorf("system tools = %d, want 2", len(sys))
	}
}

func TestIsInstalled(t *testing.T) {
	// "ls" should always be available
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "ls", Binary: "ls", Category: "test"})
	r.Add(ToolDef{Name: "nonexistent_tool_xyz", Binary: "nonexistent_tool_xyz", Category: "test"})

	installed := r.Installed()
	found := false
	for _, td := range installed {
		if td.Name == "ls" {
			found = true
		}
		if td.Name == "nonexistent_tool_xyz" {
			t.Error("nonexistent tool should not be installed")
		}
	}
	if !found {
		t.Error("ls should be installed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/tools/ -v`
Expected: FAIL

- [ ] **Step 3: Implement registry.go**

```go
// internal/tools/registry.go
package tools

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// ToolDef defines an external tool that scanners can use.
type ToolDef struct {
	Name       string   // unique tool name (e.g., "rkhunter")
	Binary     string   // binary name to look up in PATH (e.g., "rkhunter")
	Purpose    string   // what it does
	Category   string   // which scanner group uses it
	MinVersion string   // minimum supported version
	VersionCmd []string // command to get version (e.g., ["rkhunter", "--version"])
	VersionRe  string   // regex to extract version from output
}

// ToolStatus holds runtime info about a tool.
type ToolStatus struct {
	Def       ToolDef
	Installed bool
	Path      string // resolved path
	Version   string // detected version
}

// ToolRegistry manages external tool definitions and discovery.
type ToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]ToolDef
	order []string
}

func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]ToolDef),
	}
}

func (r *ToolRegistry) Add(td ToolDef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[td.Name]; !exists {
		r.order = append(r.order, td.Name)
	}
	r.tools[td.Name] = td
}

func (r *ToolRegistry) Get(name string) (ToolDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	td, ok := r.tools[name]
	return td, ok
}

func (r *ToolRegistry) All() []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ToolDef, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.tools[name])
	}
	return result
}

func (r *ToolRegistry) ByCategory(cat string) []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []ToolDef
	for _, name := range r.order {
		if r.tools[name].Category == cat {
			result = append(result, r.tools[name])
		}
	}
	return result
}

// Installed returns tools that are found in PATH.
func (r *ToolRegistry) Installed() []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []ToolDef
	for _, name := range r.order {
		td := r.tools[name]
		if _, err := exec.LookPath(td.Binary); err == nil {
			result = append(result, td)
		}
	}
	return result
}

// Check returns detailed status for a tool.
func (r *ToolRegistry) Check(name string) ToolStatus {
	td, ok := r.Get(name)
	if !ok {
		return ToolStatus{}
	}
	status := ToolStatus{Def: td}
	path, err := exec.LookPath(td.Binary)
	if err != nil {
		return status
	}
	status.Installed = true
	status.Path = path

	// Try to get version
	if len(td.VersionCmd) > 0 {
		out, err := exec.Command(td.VersionCmd[0], td.VersionCmd[1:]...).CombinedOutput()
		if err == nil && td.VersionRe != "" {
			re := regexp.MustCompile(td.VersionRe)
			if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
				status.Version = strings.TrimSpace(m[1])
			}
		}
	}
	return status
}

// CheckAll returns status for all registered tools.
func (r *ToolRegistry) CheckAll() []ToolStatus {
	all := r.All()
	results := make([]ToolStatus, len(all))
	for i, td := range all {
		results[i] = r.Check(td.Name)
	}
	return results
}

// DefaultToolRegistry returns a registry with all known external tools.
func DefaultToolRegistry() *ToolRegistry {
	r := NewToolRegistry()

	// System / Rootkit
	r.Add(ToolDef{Name: "rkhunter", Binary: "rkhunter", Purpose: "Rootkit detection", Category: "system", MinVersion: "1.4.6", VersionCmd: []string{"rkhunter", "--version"}, VersionRe: `Rootkit Hunter (\d+\.\d+\.\d+)`})
	r.Add(ToolDef{Name: "chkrootkit", Binary: "chkrootkit", Purpose: "Rootkit detection", Category: "system", MinVersion: "0.55", VersionCmd: []string{"chkrootkit", "-V"}, VersionRe: `chkrootkit version (\d+\.\d+)`})
	r.Add(ToolDef{Name: "lynis", Binary: "lynis", Purpose: "Security auditing", Category: "system", MinVersion: "3.0.0", VersionCmd: []string{"lynis", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// Malware
	r.Add(ToolDef{Name: "clamav", Binary: "clamscan", Purpose: "Malware/virus scanning", Category: "malware", MinVersion: "0.103", VersionCmd: []string{"clamscan", "--version"}, VersionRe: `ClamAV (\d+\.\d+\.\d+)`})

	// Secrets
	r.Add(ToolDef{Name: "gitleaks", Binary: "gitleaks", Purpose: "Secret detection in git repos", Category: "secrets", MinVersion: "8.0.0", VersionCmd: []string{"gitleaks", "version"}, VersionRe: `(\d+\.\d+\.\d+)`})
	r.Add(ToolDef{Name: "trufflehog", Binary: "trufflehog", Purpose: "Secret detection across filesystems", Category: "secrets", MinVersion: "3.0.0", VersionCmd: []string{"trufflehog", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// Dependencies / Supply chain
	r.Add(ToolDef{Name: "trivy", Binary: "trivy", Purpose: "Vulnerability scanning", Category: "dependencies", MinVersion: "0.40.0", VersionCmd: []string{"trivy", "version"}, VersionRe: `Version: (\d+\.\d+\.\d+)`})
	r.Add(ToolDef{Name: "grype", Binary: "grype", Purpose: "Vulnerability scanning", Category: "dependencies", MinVersion: "0.60.0", VersionCmd: []string{"grype", "version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// Containers
	r.Add(ToolDef{Name: "hadolint", Binary: "hadolint", Purpose: "Dockerfile linting", Category: "containers", MinVersion: "2.10.0", VersionCmd: []string{"hadolint", "--version"}, VersionRe: `Haskell Dockerfile Linter (\d+\.\d+\.\d+)`})
	r.Add(ToolDef{Name: "dockle", Binary: "dockle", Purpose: "Container best practices", Category: "containers", MinVersion: "0.4.0", VersionCmd: []string{"dockle", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// SSH
	r.Add(ToolDef{Name: "ssh-audit", Binary: "ssh-audit", Purpose: "SSH server/client auditing", Category: "ssh", MinVersion: "2.5.0", VersionCmd: []string{"ssh-audit", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// Code
	r.Add(ToolDef{Name: "semgrep", Binary: "semgrep", Purpose: "Static analysis", Category: "code", MinVersion: "1.0.0", VersionCmd: []string{"semgrep", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})
	r.Add(ToolDef{Name: "bandit", Binary: "bandit", Purpose: "Python security linting", Category: "code", MinVersion: "1.7.0", VersionCmd: []string{"bandit", "--version"}, VersionRe: `(\d+\.\d+\.\d+)`})

	// Network
	r.Add(ToolDef{Name: "nmap", Binary: "nmap", Purpose: "Network scanning", Category: "network", MinVersion: "7.80", VersionCmd: []string{"nmap", "--version"}, VersionRe: `Nmap version (\d+\.\d+)`})
	r.Add(ToolDef{Name: "ss", Binary: "ss", Purpose: "Socket statistics", Category: "network"})

	// File integrity
	r.Add(ToolDef{Name: "aide", Binary: "aide", Purpose: "File integrity checking", Category: "filesystem", MinVersion: "0.17", VersionCmd: []string{"aide", "--version"}, VersionRe: `Aide (\d+\.\d+)`})

	// Package forensics
	r.Add(ToolDef{Name: "debsums", Binary: "debsums", Purpose: "Verify installed package checksums", Category: "forensics"})

	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/company/nunenuh/defense-kit/defense-kit-cli && go test ./internal/tools/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add defense-kit-cli/internal/tools/
git commit -m "feat: add external tool registry with discovery and version checking"
```

---

### Task 2: Tool Runner — Safe External Command Execution

**Files:**
- Create: `defense-kit-cli/internal/tools/runner.go`
- Modify: `defense-kit-cli/internal/tools/tools_test.go`

- [ ] **Step 1: Write failing test**

```go
// Add to tools_test.go
func TestRunnerExec(t *testing.T) {
	r := NewRunner()
	ctx := context.Background()
	out, err := r.Run(ctx, "echo", []string{"hello", "world"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "hello world") {
		t.Errorf("output = %q, want 'hello world'", out)
	}
}

func TestRunnerExecNotFound(t *testing.T) {
	r := NewRunner()
	ctx := context.Background()
	_, err := r.Run(ctx, "nonexistent_binary_xyz", nil)
	if err == nil {
		t.Fatal("should fail for nonexistent binary")
	}
}

func TestRunnerTimeout(t *testing.T) {
	r := NewRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := r.Run(ctx, "sleep", []string{"10"})
	if err == nil {
		t.Fatal("should timeout")
	}
}

func TestRunnerAvailable(t *testing.T) {
	r := NewRunner()
	if !r.Available("echo") {
		t.Error("echo should be available")
	}
	if r.Available("nonexistent_binary_xyz") {
		t.Error("nonexistent should not be available")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement runner.go**

```go
// internal/tools/runner.go
package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Runner executes external tools safely using exec.CommandContext.
// No shell interpretation — all commands use explicit argv.
type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

// Run executes a tool with the given arguments.
// Uses exec.CommandContext — no shell interpretation.
func (r *Runner) Run(ctx context.Context, tool string, args []string) ([]byte, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return nil, fmt.Errorf("tool not found: %s", tool)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s failed: %w (stderr: %s)", tool, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// RunWithStderr executes a tool and returns both stdout and stderr.
func (r *Runner) RunWithStderr(ctx context.Context, tool string, args []string) (stdout, stderr []byte, err error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return nil, nil, fmt.Errorf("tool not found: %s", tool)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), runErr
}

// RunJSON executes a tool and returns raw JSON output (caller parses).
func (r *Runner) RunJSON(ctx context.Context, tool string, args []string) ([]byte, error) {
	out, err := r.Run(ctx, tool, args)
	if err != nil {
		return out, err
	}
	return out, nil
}

// Available checks if a tool is in PATH.
func (r *Runner) Available(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// RunPython executes a Python script with arguments.
func (r *Runner) RunPython(ctx context.Context, pythonPath, script string, args []string) ([]byte, error) {
	if pythonPath == "" {
		pythonPath = "python3"
	}
	fullArgs := append([]string{script}, args...)
	return r.Run(ctx, pythonPath, fullArgs)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/tools/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add defense-kit-cli/internal/tools/
git commit -m "feat: add tool runner for safe external command execution"
```

---

### Task 3: Output Parsers — Convert Tool Output to Findings

**Files:**
- Create: `defense-kit-cli/internal/tools/parser.go`
- Create: `defense-kit-cli/internal/tools/parser_test.go`

Parsers convert raw tool output into `[]scanner.Finding`. Each supported tool gets a parser function.

- [ ] **Step 1: Write failing tests with captured tool output**

```go
// internal/tools/parser_test.go
package tools

import (
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func TestParseGitleaksJSON(t *testing.T) {
	// Captured from: gitleaks detect --report-format json
	sample := `[
		{
			"Description": "AWS Access Key",
			"StartLine": 5,
			"EndLine": 5,
			"File": "config.py",
			"Secret": "AKIAIOSFODNN7EXAMPLE",
			"Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			"RuleID": "aws-access-key-id"
		}
	]`
	findings, err := ParseGitleaksJSON([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != scanner.SevCritical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
	if findings[0].Scanner != "gitleaks" {
		t.Errorf("scanner = %s", findings[0].Scanner)
	}
}

func TestParseTrivyJSON(t *testing.T) {
	// Captured from: trivy fs --format json
	sample := `{
		"Results": [
			{
				"Target": "requirements.txt",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-1234",
						"PkgName": "requests",
						"InstalledVersion": "2.28.0",
						"FixedVersion": "2.31.0",
						"Severity": "HIGH",
						"Title": "SSRF vulnerability in requests",
						"Description": "A server-side request forgery vulnerability."
					}
				]
			}
		]
	}`
	findings, err := ParseTrivyJSON([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Severity != scanner.SevHigh {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
	if findings[0].Scanner != "trivy" {
		t.Errorf("scanner = %s", findings[0].Scanner)
	}
}

func TestParseRkhunterOutput(t *testing.T) {
	sample := `[ Rootkit Hunter version 1.4.6 ]
Checking system commands...
  Performing 'strings' command checks
    Checking 'strings' command                               [ OK ]
  Performing file properties checks
    /usr/bin/awk                                             [ OK ]
    /usr/bin/curl                                            [ Warning ]
Checking for rootkits...
  Performing check of known rootkit files and directories
    55808 Trojan - Variant A                                 [ Not found ]
    ADM Worm                                                 [ Not found ]
    Suspicious file /tmp/.hidden                             [ Warning ]
`
	findings, err := ParseRkhunterOutput([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("should find warnings")
	}
	hasWarning := false
	for _, f := range findings {
		if f.Severity >= scanner.SevHigh {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Error("should have HIGH+ severity findings from warnings")
	}
}

func TestParseSSHAuditJSON(t *testing.T) {
	sample := `{
		"banner": {
			"raw": "SSH-2.0-OpenSSH_8.9p1"
		},
		"recommendations": [
			{
				"key": "del",
				"value": "diffie-hellman-group14-sha1",
				"severity": "warn"
			},
			{
				"key": "del",
				"value": "hmac-sha1",
				"severity": "fail"
			}
		]
	}`
	findings, err := ParseSSHAuditJSON([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 1 {
		t.Fatal("should find recommendations")
	}
}

func TestParseEmptyInput(t *testing.T) {
	f, err := ParseGitleaksJSON([]byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Error("empty array should produce 0 findings")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement parser.go**

Implement parsers for: gitleaks (JSON), trivy (JSON), rkhunter (text/regex), ssh-audit (JSON). Each parser:
- Takes `[]byte` raw output
- Returns `[]scanner.Finding, error`
- Maps tool severity levels to our Severity enum
- Generates finding IDs with `scanner.GenerateFindingID`

```go
// internal/tools/parser.go
package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// --- Gitleaks ---

type gitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
	RuleID      string `json:"RuleID"`
}

func ParseGitleaksJSON(data []byte) ([]scanner.Finding, error) {
	var results []gitleaksResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("gitleaks parse error: %w", err)
	}
	findings := make([]scanner.Finding, 0, len(results))
	for _, r := range results {
		location := fmt.Sprintf("%s:%d", r.File, r.StartLine)
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("gitleaks", location, r.Description),
			Scanner:     "gitleaks",
			Severity:    scanner.SevCritical,
			Title:       fmt.Sprintf("Secret detected: %s", r.Description),
			Detail:      fmt.Sprintf("Rule: %s", r.RuleID),
			Evidence:    truncate(r.Match, 200),
			Location:    location,
			Remediation: "Rotate the exposed secret and remove it from source code",
			References:  []string{fmt.Sprintf("gitleaks-rule:%s", r.RuleID)},
		})
	}
	return findings, nil
}

// --- Trivy ---

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string        `json:"Target"`
	Vulnerabilities []trivyVuln   `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

func ParseTrivyJSON(data []byte) ([]scanner.Finding, error) {
	var output trivyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("trivy parse error: %w", err)
	}
	var findings []scanner.Finding
	for _, r := range output.Results {
		for _, v := range r.Vulnerabilities {
			location := fmt.Sprintf("%s:%s", r.Target, v.PkgName)
			remediation := "Update package"
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Update %s from %s to %s", v.PkgName, v.InstalledVersion, v.FixedVersion)
			}
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("trivy", location, v.VulnerabilityID),
				Scanner:     "trivy",
				Severity:    mapTrivySeverity(v.Severity),
				Title:       fmt.Sprintf("%s: %s", v.VulnerabilityID, v.Title),
				Detail:      v.Description,
				Evidence:    fmt.Sprintf("%s@%s (fixed: %s)", v.PkgName, v.InstalledVersion, v.FixedVersion),
				Location:    location,
				Remediation: remediation,
				References:  []string{v.VulnerabilityID},
			})
		}
	}
	return findings, nil
}

func mapTrivySeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SevCritical
	case "HIGH":
		return scanner.SevHigh
	case "MEDIUM":
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

// --- rkhunter ---

var rkhunterWarningRe = regexp.MustCompile(`(.+?)\s+\[\s*(Warning|Infected)\s*\]`)

func ParseRkhunterOutput(data []byte) ([]scanner.Finding, error) {
	var findings []scanner.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := rkhunterWarningRe.FindStringSubmatch(line); len(m) > 2 {
			severity := scanner.SevHigh
			if strings.EqualFold(m[2], "Infected") {
				severity = scanner.SevCritical
			}
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("rkhunter", m[1], m[2]),
				Scanner:     "rkhunter",
				Severity:    severity,
				Title:       fmt.Sprintf("rkhunter %s: %s", strings.ToLower(m[2]), strings.TrimSpace(m[1])),
				Evidence:    line,
				Location:    strings.TrimSpace(m[1]),
				Remediation: "Investigate the flagged item — verify legitimacy or remove if unauthorized",
			})
		}
	}
	return findings, nil
}

// --- ssh-audit ---

type sshAuditOutput struct {
	Banner struct {
		Raw string `json:"raw"`
	} `json:"banner"`
	Recommendations []sshAuditRec `json:"recommendations"`
}

type sshAuditRec struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Severity string `json:"severity"`
}

func ParseSSHAuditJSON(data []byte) ([]scanner.Finding, error) {
	var output sshAuditOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("ssh-audit parse error: %w", err)
	}
	var findings []scanner.Finding
	for _, rec := range output.Recommendations {
		severity := scanner.SevMedium
		if rec.Severity == "fail" {
			severity = scanner.SevHigh
		}
		action := rec.Key
		if action == "del" {
			action = "remove"
		}
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("ssh-audit", rec.Value, rec.Key),
			Scanner:     "ssh-audit",
			Severity:    severity,
			Title:       fmt.Sprintf("SSH: %s %s", action, rec.Value),
			Detail:      fmt.Sprintf("ssh-audit recommends to %s algorithm: %s", action, rec.Value),
			Location:    "sshd",
			Remediation: fmt.Sprintf("Edit sshd_config to %s %s", action, rec.Value),
		})
	}
	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
```

- [ ] **Step 4: Run tests**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add defense-kit-cli/internal/tools/
git commit -m "feat: add output parsers for gitleaks, trivy, rkhunter, ssh-audit"
```

---

### Task 4: Enhance Scanners with External Tool Support

**Files:**
- Modify: `defense-kit-cli/internal/scanner/types.go` — add ToolRunner field to ScanOptions
- Modify: `defense-kit-cli/internal/scanner/code/credentials.go` — add gitleaks integration
- Modify: `defense-kit-cli/internal/scanner/system/rootkit.go` — add rkhunter integration
- Modify: `defense-kit-cli/internal/scanner/auth/ssh.go` — add ssh-audit integration
- Fill stub: `defense-kit-cli/internal/scanner/code/supplychain.go` — trivy integration
- Fill stub: `defense-kit-cli/internal/scanner/code/containers.go` — hadolint integration
- Fill stub: `defense-kit-cli/internal/scanner/system/packagemgr.go` — debsums integration

- [ ] **Step 1: Add ToolRunner to ScanOptions**

Add to `internal/scanner/types.go`:

```go
// ToolRunner allows scanners to call external tools.
// If nil, scanners use native Go checks only.
type ToolRunner interface {
	Run(ctx context.Context, tool string, args []string) ([]byte, error)
	Available(tool string) bool
}
```

Add to ScanOptions:
```go
type ScanOptions struct {
    // ... existing fields ...
    ToolRunner ToolRunner // nil = native checks only
}
```

- [ ] **Step 2: Update credentials.go to use gitleaks when available**

Pattern: try external tool first, fall back to native Go:

```go
func (s *CredentialsScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
    var findings []scanner.Finding

    // Try gitleaks if available
    if opts.ToolRunner != nil && opts.ToolRunner.Available("gitleaks") {
        for _, path := range targetPaths {
            out, err := opts.ToolRunner.Run(ctx, "gitleaks", []string{
                "detect", "--source", path, "--report-format", "json", "--no-git",
            })
            if err == nil {
                toolFindings, _ := tools.ParseGitleaksJSON(out)
                findings = append(findings, toolFindings...)
            }
        }
    }

    // Always run native checks too (catches things gitleaks might miss)
    nativeFindings, err := s.nativeScan(ctx, opts)
    findings = append(findings, nativeFindings...)

    return dedup(findings), err
}
```

- [ ] **Step 3: Update rootkit.go to use rkhunter when available**

Same pattern: run rkhunter, parse output, merge with native checks.

- [ ] **Step 4: Update ssh.go to use ssh-audit when available**

Run `ssh-audit --json localhost`, parse recommendations.

- [ ] **Step 5: Fill supplychain.go stub with trivy integration**

```go
func (s *SupplyChainScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
    if opts.ToolRunner == nil || !opts.ToolRunner.Available("trivy") {
        return nil, nil // no native fallback yet
    }
    var findings []scanner.Finding
    for _, path := range opts.TargetPaths {
        out, err := opts.ToolRunner.Run(ctx, "trivy", []string{
            "fs", "--format", "json", "--quiet", path,
        })
        if err != nil {
            continue
        }
        f, _ := tools.ParseTrivyJSON(out)
        findings = append(findings, f...)
    }
    return findings, nil
}
```

- [ ] **Step 6: Fill containers.go stub with hadolint**

Scan for Dockerfiles, run `hadolint --format json`, parse output.

- [ ] **Step 7: Fill packagemgr.go stub with debsums**

Run `debsums -c` to find modified package files. Parse text output.

- [ ] **Step 8: Update RequiredTools/OptionalTools on enhanced scanners**

Each enhanced scanner should now report which external tools it can use:
```go
func (s *CredentialsScanner) OptionalTools() []string { return []string{"gitleaks", "trufflehog"} }
```

- [ ] **Step 9: Run all tests**

Run: `go test ./... -v -race`
Expected: All pass (existing tests should not break since ToolRunner is nil in test opts)

- [ ] **Step 10: Commit**

```bash
git add defense-kit-cli/internal/
git commit -m "feat: integrate external tools into scanners (gitleaks, trivy, rkhunter, ssh-audit, hadolint, debsums)"
```

---

### Task 5: Wire Tool Runner into CLI + Update tools check

**Files:**
- Modify: `defense-kit-cli/cmd/defense-kit/main.go`
- Modify: `defense-kit-cli/cmd/defense-kit/register.go`

- [ ] **Step 1: Wire ToolRunner into runScan**

In `runScan`, create a `tools.Runner` and pass it to `ScanOptions.ToolRunner`:

```go
toolRunner := tools.NewRunner()
opts := scanner.ScanOptions{
    // ... existing fields ...
    ToolRunner: toolRunner,
}
```

- [ ] **Step 2: Update tools check to show external tools**

Add external tool listing to `runToolsCheck`:
```go
// After listing scanners, list external tools:
toolReg := tools.DefaultToolRegistry()
statuses := toolReg.CheckAll()
// Print table: name, installed, version, path
```

- [ ] **Step 3: Build and verify**

Run: `make build && ./bin/defense-kit tools check`
Expected: Shows both scanners and external tools with install status + versions

- [ ] **Step 4: Commit**

```bash
git add defense-kit-cli/cmd/defense-kit/
git commit -m "feat: wire tool runner into scan pipeline, enhance tools check with versions"
```

---

### Task 6: Create REGISTRY.md and PIPELINES.md Documentation

**Files:**
- Create: `tools/REGISTRY.md`
- Create: `tools/PIPELINES.md`

- [ ] **Step 1: Write REGISTRY.md**

Document all 17+ external tools following pentest-kit's pattern:
- Name, purpose, category, install command, binary, version check, minimum version
- For each tool: what scanners use it, what it adds over native checks

- [ ] **Step 2: Write PIPELINES.md**

Document the 3 scan pipelines:
- full_scan: all 30 categories, max parallelism
- quick_monitor: fast subset for /loop
- incident_response: targeted compromise detection

- [ ] **Step 3: Commit**

```bash
git add tools/
git commit -m "docs: add REGISTRY.md and PIPELINES.md for external tool catalog"
```

---

### Task 7: End-to-End Verification

- [ ] **Step 1: Full scan with tools available**

Run: `./bin/defense-kit scan`
Expected: Scanners that find external tools use them, others fall back to native

- [ ] **Step 2: Tools check shows versions**

Run: `./bin/defense-kit tools check`
Expected: External tools section with installed/version info

- [ ] **Step 3: Scan without tools still works**

Run: `./bin/defense-kit scan` (in environment without tools)
Expected: All native checks run, no errors from missing tools

- [ ] **Step 4: Run test suite**

Run: `go test ./... -race -cover`
Expected: All pass, coverage maintained

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: defense-kit v2 phase 2 complete — external tool integration"
```
