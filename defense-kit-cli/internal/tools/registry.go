// Package tools provides a thread-safe registry of external security tools
// used by the defense-kit scanners, together with helpers that probe the
// host system to determine which tools are available.
package tools

import (
	"os/exec"
	"regexp"
	"sync"
)

// ToolDef describes a single external security tool.
type ToolDef struct {
	// Name is the canonical identifier used to look up the tool in the registry.
	Name string
	// Binary is the executable name looked up via PATH (e.g. "clamscan").
	Binary string
	// Purpose is a short human-readable description of what the tool does.
	Purpose string
	// Category groups related tools together (e.g. "system", "secrets").
	Category string
	// MinVersion is the minimum required version string (informational).
	MinVersion string
	// VersionCmd is the command used to query the tool's version.
	VersionCmd []string
	// VersionRe is a regular expression with one capture group that extracts
	// the version string from the output of VersionCmd.
	VersionRe string
}

// ToolStatus is the result of checking whether a tool is present on the host.
type ToolStatus struct {
	// Def is the tool definition from the registry.
	Def ToolDef
	// Installed is true when the binary was found in PATH.
	Installed bool
	// Path is the absolute path of the binary, or empty when not installed.
	Path string
	// Version is the extracted version string, or empty when not detected.
	Version string
}

// ToolRegistry is a thread-safe collection of ToolDef values.
type ToolRegistry struct {
	mu    sync.RWMutex
	defs  []ToolDef          // preserves insertion order
	byName map[string]ToolDef // fast name lookup
}

// NewToolRegistry returns an initialised, empty ToolRegistry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		byName: make(map[string]ToolDef),
	}
}

// Add registers td in the registry. If a tool with the same Name was already
// registered it is silently replaced in-place so that insertion order is
// preserved for existing entries.
func (r *ToolRegistry) Add(td ToolDef) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byName[td.Name]; !exists {
		r.defs = append(r.defs, td)
	} else {
		for i, existing := range r.defs {
			if existing.Name == td.Name {
				r.defs[i] = td
				break
			}
		}
	}
	r.byName[td.Name] = td
}

// Get returns the ToolDef registered under name together with a boolean
// indicating whether the entry was found.
func (r *ToolRegistry) Get(name string) (ToolDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	td, ok := r.byName[name]
	return td, ok
}

// All returns a copy of every registered ToolDef in insertion order.
func (r *ToolRegistry) All() []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ToolDef, len(r.defs))
	copy(out, r.defs)
	return out
}

// ByCategory returns all ToolDef values whose Category equals cat.
func (r *ToolRegistry) ByCategory(cat string) []ToolDef {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []ToolDef
	for _, td := range r.defs {
		if td.Category == cat {
			out = append(out, td)
		}
	}
	return out
}

// Installed returns all ToolDef values whose Binary is found in PATH.
func (r *ToolRegistry) Installed() []ToolDef {
	r.mu.RLock()
	defs := make([]ToolDef, len(r.defs))
	copy(defs, r.defs)
	r.mu.RUnlock()

	var out []ToolDef
	for _, td := range defs {
		if _, err := exec.LookPath(td.Binary); err == nil {
			out = append(out, td)
		}
	}
	return out
}

// Check returns a ToolStatus for the tool registered under name. When name is
// not registered the returned status has Installed set to false and an empty
// Def.
func (r *ToolRegistry) Check(name string) ToolStatus {
	td, ok := r.Get(name)
	if !ok {
		return ToolStatus{}
	}
	return checkTool(td)
}

// CheckAll returns a ToolStatus for every registered tool.
func (r *ToolRegistry) CheckAll() []ToolStatus {
	all := r.All()
	out := make([]ToolStatus, 0, len(all))
	for _, td := range all {
		out = append(out, checkTool(td))
	}
	return out
}

// checkTool probes the host to determine whether td's binary is present and
// attempts to extract its version string.
func checkTool(td ToolDef) ToolStatus {
	path, err := exec.LookPath(td.Binary)
	if err != nil {
		return ToolStatus{Def: td, Installed: false}
	}

	status := ToolStatus{
		Def:       td,
		Installed: true,
		Path:      path,
	}

	if len(td.VersionCmd) > 0 && td.VersionRe != "" {
		status.Version = detectVersion(td.VersionCmd, td.VersionRe)
	}

	return status
}

// detectVersion runs cmd and extracts a version string using re.
func detectVersion(cmd []string, re string) string {
	if len(cmd) == 0 {
		return ""
	}

	//nolint:gosec // cmd is sourced from hard-coded ToolDef values, not user input.
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}

	compiled, err := regexp.Compile(re)
	if err != nil {
		return ""
	}

	matches := compiled.FindSubmatch(out)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
}

// DefaultToolRegistry returns a ToolRegistry pre-populated with the 17
// standard security tools used by defense-kit.
func DefaultToolRegistry() *ToolRegistry {
	r := NewToolRegistry()

	tools := []ToolDef{
		// system
		{
			Name:       "rkhunter",
			Binary:     "rkhunter",
			Purpose:    "Rootkit, backdoor, and local exploit scanner",
			Category:   "system",
			MinVersion: "1.4",
			VersionCmd: []string{"rkhunter", "--version"},
			VersionRe:  `Rootkit Hunter (\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "chkrootkit",
			Binary:     "chkrootkit",
			Purpose:    "Locally checks for signs of a rootkit",
			Category:   "system",
			MinVersion: "0.55",
			VersionCmd: []string{"chkrootkit", "-V"},
			VersionRe:  `chkrootkit version (\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "lynis",
			Binary:     "lynis",
			Purpose:    "Security auditing tool for Unix/Linux systems",
			Category:   "system",
			MinVersion: "3.0",
			VersionCmd: []string{"lynis", "--version"},
			VersionRe:  `(\d+\.\d+\.\d+)`,
		},
		// malware
		{
			Name:       "clamscan",
			Binary:     "clamscan",
			Purpose:    "ClamAV antivirus scanner",
			Category:   "malware",
			MinVersion: "0.103",
			VersionCmd: []string{"clamscan", "--version"},
			VersionRe:  `ClamAV (\d+\.\d+[\.\d]*)`,
		},
		// secrets
		{
			Name:       "gitleaks",
			Binary:     "gitleaks",
			Purpose:    "Detect secrets and sensitive information in git repositories",
			Category:   "secrets",
			MinVersion: "8.0",
			VersionCmd: []string{"gitleaks", "version"},
			VersionRe:  `v?(\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "trufflehog",
			Binary:     "trufflehog",
			Purpose:    "Find credentials and secrets in git history",
			Category:   "secrets",
			MinVersion: "3.0",
			VersionCmd: []string{"trufflehog", "--version"},
			VersionRe:  `trufflehog (\d+\.\d+[\.\d]*)`,
		},
		// dependencies
		{
			Name:       "trivy",
			Binary:     "trivy",
			Purpose:    "Vulnerability scanner for containers and filesystems",
			Category:   "dependencies",
			MinVersion: "0.40",
			VersionCmd: []string{"trivy", "--version"},
			VersionRe:  `Version: (\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "grype",
			Binary:     "grype",
			Purpose:    "Vulnerability scanner for container images and filesystems",
			Category:   "dependencies",
			MinVersion: "0.60",
			VersionCmd: []string{"grype", "version"},
			VersionRe:  `Application Version:\s+(\d+\.\d+[\.\d]*)`,
		},
		// containers
		{
			Name:       "hadolint",
			Binary:     "hadolint",
			Purpose:    "Dockerfile linter that helps build best practice Docker images",
			Category:   "containers",
			MinVersion: "2.0",
			VersionCmd: []string{"hadolint", "--version"},
			VersionRe:  `Haskell Dockerfile Linter (\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "dockle",
			Binary:     "dockle",
			Purpose:    "Container image linter for security best practices",
			Category:   "containers",
			MinVersion: "0.4",
			VersionCmd: []string{"dockle", "--version"},
			VersionRe:  `dockle version (\d+\.\d+[\.\d]*)`,
		},
		// ssh
		{
			Name:       "ssh-audit",
			Binary:     "ssh-audit",
			Purpose:    "SSH server and client configuration auditor",
			Category:   "ssh",
			MinVersion: "3.0",
			VersionCmd: []string{"ssh-audit", "--version"},
			VersionRe:  `(\d+\.\d+[\.\d]*)`,
		},
		// code
		{
			Name:       "semgrep",
			Binary:     "semgrep",
			Purpose:    "Static analysis tool for finding bugs and security issues",
			Category:   "code",
			MinVersion: "1.0",
			VersionCmd: []string{"semgrep", "--version"},
			VersionRe:  `(\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "bandit",
			Binary:     "bandit",
			Purpose:    "Security linter for Python code",
			Category:   "code",
			MinVersion: "1.7",
			VersionCmd: []string{"bandit", "--version"},
			VersionRe:  `bandit (\d+\.\d+[\.\d]*)`,
		},
		// network
		{
			Name:       "nmap",
			Binary:     "nmap",
			Purpose:    "Network exploration and security auditing tool",
			Category:   "network",
			MinVersion: "7.0",
			VersionCmd: []string{"nmap", "--version"},
			VersionRe:  `Nmap version (\d+\.\d+[\.\d]*)`,
		},
		{
			Name:       "ss",
			Binary:     "ss",
			Purpose:    "Utility to investigate sockets and network connections",
			Category:   "network",
			MinVersion: "",
			VersionCmd: []string{"ss", "-V"},
			VersionRe:  `ss utility, iproute2-ss(\S+)`,
		},
		// filesystem
		{
			Name:       "aide",
			Binary:     "aide",
			Purpose:    "Advanced Intrusion Detection Environment — file integrity checker",
			Category:   "filesystem",
			MinVersion: "0.17",
			VersionCmd: []string{"aide", "--version"},
			VersionRe:  `Aide (\d+\.\d+[\.\d]*)`,
		},
		// forensics
		{
			Name:       "debsums",
			Binary:     "debsums",
			Purpose:    "Verify installed Debian package checksums",
			Category:   "forensics",
			MinVersion: "3.0",
			VersionCmd: []string{"debsums", "--version"},
			VersionRe:  `debsums (\d+\.\d+[\.\d]*)`,
		},
	}

	for _, td := range tools {
		r.Add(td)
	}
	return r
}
