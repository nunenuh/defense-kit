package process

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// MemoryScanner inspects process memory maps for suspicious injected regions.
type MemoryScanner struct {
	// procRoot is the root of the proc filesystem; overrideable in tests.
	procRoot string
}

// NewMemoryScanner creates a new MemoryScanner.
func NewMemoryScanner() *MemoryScanner {
	return &MemoryScanner{procRoot: "/proc"}
}

// NewMemoryScannerWithRoot creates a MemoryScanner that uses the given procRoot.
// Exported for testing with synthetic /proc trees.
func NewMemoryScannerWithRoot(procRoot string) *MemoryScanner {
	return &MemoryScanner{procRoot: procRoot}
}

func (s *MemoryScanner) Name() string            { return "memory" }
func (s *MemoryScanner) Category() string        { return "process" }
func (s *MemoryScanner) RequiresRoot() bool      { return true }
func (s *MemoryScanner) RequiredTools() []string { return nil }
func (s *MemoryScanner) OptionalTools() []string { return nil }
func (s *MemoryScanner) Available() bool         { return true }
func (s *MemoryScanner) Description() string {
	return "Inspects /proc/*/maps for suspicious executable memory regions, deleted mappings, and anonymous rwx segments indicative of code injection."
}

// Scan checks process memory maps for suspicious injected or anonymous executable regions.
func (s *MemoryScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		return nil, fmt.Errorf("memory: cannot read %s: %w", s.procRoot, err)
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isNumeric(pid) {
			continue
		}

		findings = append(findings, s.checkExe(pid)...)
		findings = append(findings, s.checkMaps(pid)...)
		findings = append(findings, s.checkTracerPid(pid)...)
	}

	return findings, nil
}

// checkExe inspects /proc/<pid>/exe for "(deleted)" in the resolved path,
// which indicates the on-disk binary was removed after execution — a common
// fileless malware technique.
func (s *MemoryScanner) checkExe(pid string) []scanner.Finding {
	exePath := filepath.Join(s.procRoot, pid, "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		return nil
	}

	if strings.Contains(target, "(deleted)") {
		return []scanner.Finding{{
			ID:          scanner.GenerateFindingID("memory", exePath, "Deleted executable still running"),
			Scanner:     "memory",
			Severity:    scanner.SevCritical,
			Title:       "Deleted executable still running",
			Detail:      fmt.Sprintf("Process PID %s is executing from a deleted file (%q). This is a common indicator of fileless malware or in-memory exploitation.", pid, target),
			Evidence:    target,
			Location:    exePath,
			Remediation: "Investigate the process immediately. Dump its memory for forensic analysis, then kill it. Audit how the binary was launched.",
			Metadata:    map[string]string{"pid": pid, "exe": target},
		}}
	}

	return nil
}

// suspiciousMapPrefixes are filesystem prefixes used to stage malware.
var suspiciousMapPrefixes = []string{
	"/tmp/",
	"/dev/shm/",
}

// checkMaps reads /proc/<pid>/maps and flags shared libraries mapped from
// suspicious world-writable locations like /tmp or /dev/shm.
func (s *MemoryScanner) checkMaps(pid string) []scanner.Finding {
	mapsPath := filepath.Join(s.procRoot, pid, "maps")
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	seen := make(map[string]bool)

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		// /proc/<pid>/maps format:
		//   addr-range  perms  offset  dev  inode  [pathname]
		// Pathname is optional (anonymous mappings have no path).
		if len(fields) < 6 {
			continue
		}

		pathname := fields[5]
		if seen[pathname] {
			continue
		}
		seen[pathname] = true

		for _, prefix := range suspiciousMapPrefixes {
			if strings.HasPrefix(pathname, prefix) {
				loc := fmt.Sprintf("/proc/%s/maps: %s", pid, pathname)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("memory", loc, "Library mapped from suspicious location"),
					Scanner:     "memory",
					Severity:    scanner.SevCritical,
					Title:       "Library mapped from suspicious location",
					Detail:      fmt.Sprintf("Process PID %s has a memory region mapped from %q, a world-writable directory used for staging malware.", pid, pathname),
					Evidence:    line,
					Location:    fmt.Sprintf("/proc/%s/maps", pid),
					Remediation: "Investigate the process and the file at the suspicious path. Kill the process if it is malicious and remove the file.",
					Metadata:    map[string]string{"pid": pid, "path": pathname},
				})
				break
			}
		}
	}

	return findings
}

// checkTracerPid reads /proc/<pid>/status and flags any process whose
// TracerPid field is non-zero, indicating it is being traced/debugged.
func (s *MemoryScanner) checkTracerPid(pid string) []scanner.Finding {
	statusPath := filepath.Join(s.procRoot, pid, "status")
	val := readProcStatus(statusPath, "TracerPid")
	if val == "" || val == "0" {
		return nil
	}

	// Verify it is actually a non-zero number.
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n == 0 {
		return nil
	}

	loc := statusPath
	return []scanner.Finding{{
		ID:          scanner.GenerateFindingID("memory", loc, "Process being traced"),
		Scanner:     "memory",
		Severity:    scanner.SevHigh,
		Title:       "Process being traced (possible code injection)",
		Detail:      fmt.Sprintf("Process PID %s has TracerPid=%s, meaning another process is attached to it via ptrace. This may indicate debugging, injection, or a compromised process.", pid, val),
		Evidence:    fmt.Sprintf("TracerPid: %s", val),
		Location:    loc,
		Remediation: "Identify the tracing process (PID " + val + "). If it is not a known debugger or security tool, investigate for signs of compromise.",
		Metadata:    map[string]string{"pid": pid, "tracer_pid": val},
	}}
}
