package persistence

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const xdgRecentDays = 7

// xdgSuspiciousExecSubstrings are substrings in an Exec= line that indicate
// potentially malicious autostart entries.
var xdgSuspiciousExecSubstrings = []string{
	"curl",
	"wget",
	"bash",
	"eval",
	"base64",
}

// suspiciousExecPaths are directory prefixes that indicate the binary is
// running from a world-writable or temporary location.
var suspiciousExecPaths = []string{
	"/tmp",
	"/dev/shm",
}

// systemXDGAutostartDir is the system-wide XDG autostart directory.
const systemXDGAutostartDir = "/etc/xdg/autostart"

// XDGAutoStartScanner detects persistence via XDG .desktop autostart files.
type XDGAutoStartScanner struct {
	systemDir string
	homeBase  string
}

// NewXDGAutoStartScanner creates a new XDGAutoStartScanner with production defaults.
func NewXDGAutoStartScanner() *XDGAutoStartScanner {
	return &XDGAutoStartScanner{
		systemDir: systemXDGAutostartDir,
		homeBase:  "/home",
	}
}

// newXDGAutoStartScannerWithPaths creates an XDGAutoStartScanner with custom
// paths for testing.
func newXDGAutoStartScannerWithPaths(systemDir, homeBase string) *XDGAutoStartScanner {
	return &XDGAutoStartScanner{
		systemDir: systemDir,
		homeBase:  homeBase,
	}
}

// NewXDGAutoStartScannerWithHomeBase creates an XDGAutoStartScanner that uses
// the given directory as homeBase (scans <homeBase>/*/.config/autostart).
// For testing: place user dirs directly under homeBase.
func NewXDGAutoStartScannerWithHomeBase(homeBase string) *XDGAutoStartScanner {
	return &XDGAutoStartScanner{
		systemDir: "", // no system-wide dir
		homeBase:  homeBase,
	}
}

func (s *XDGAutoStartScanner) Name() string            { return "xdg_autostart" }
func (s *XDGAutoStartScanner) Category() string        { return "persistence" }
func (s *XDGAutoStartScanner) RequiresRoot() bool      { return false }
func (s *XDGAutoStartScanner) RequiredTools() []string { return nil }
func (s *XDGAutoStartScanner) OptionalTools() []string { return nil }
func (s *XDGAutoStartScanner) Available() bool         { return true }
func (s *XDGAutoStartScanner) Description() string {
	return "Detects persistence via XDG .desktop autostart files in /etc/xdg/autostart and ~/.config/autostart. Flags unknown binaries not owned by any package, execution from /tmp or /dev/shm, and suspicious patterns (curl, wget, bash, eval, base64)."
}

// Scan inspects XDG autostart directories for suspicious .desktop entries.
func (s *XDGAutoStartScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	dirs := s.collectAutostartDirs()

	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	addFinding := func(f scanner.Finding) {
		if !seenIDs[f.ID] {
			seenIDs[f.ID] = true
			findings = append(findings, f)
		}
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.ToLower(filepath.Ext(entry.Name())) != ".desktop" {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}
			isRecent := time.Since(info.ModTime()) < xdgRecentDays*24*time.Hour

			ff := s.scanDesktopFile(path, isRecent)
			for _, f := range ff {
				addFinding(f)
			}
		}
	}

	return findings, nil
}

// collectAutostartDirs returns all autostart directories to scan.
func (s *XDGAutoStartScanner) collectAutostartDirs() []string {
	dirs := []string{s.systemDir}

	// Add ~/.config/autostart for each user in homeBase.
	entries, err := os.ReadDir(s.homeBase)
	if err != nil {
		return dirs
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		userAutostart := filepath.Join(s.homeBase, e.Name(), ".config", "autostart")
		dirs = append(dirs, userAutostart)
	}
	return dirs
}

// scanDesktopFile parses a single .desktop file and returns any findings.
func (s *XDGAutoStartScanner) scanDesktopFile(path string, isRecent bool) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Extract the Name and Exec fields.
	var entryName, execLine string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Name=") && entryName == "" {
			entryName = strings.TrimPrefix(line, "Name=")
		}
		if strings.HasPrefix(line, "Exec=") && execLine == "" {
			execLine = strings.TrimPrefix(line, "Exec=")
		}
	}

	if execLine == "" {
		return nil
	}

	if entryName == "" {
		entryName = filepath.Base(path)
	}

	// Extract the binary (first token of Exec= before any arguments).
	binary := strings.Fields(execLine)[0]
	// Strip env var prefix patterns like "env FOO=BAR /usr/bin/app".
	if strings.EqualFold(binary, "env") {
		fields := strings.Fields(execLine)
		for i := 1; i < len(fields); i++ {
			if !strings.Contains(fields[i], "=") {
				binary = fields[i]
				break
			}
		}
	}

	var findings []scanner.Finding

	// Check for critical patterns: suspicious exec paths or dangerous commands.
	for _, pattern := range xdgSuspiciousExecSubstrings {
		if strings.Contains(strings.ToLower(execLine), pattern) {
			sev := scanner.SevCritical
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("xdg_autostart", path, "suspicious exec pattern: "+pattern),
				Scanner:     "xdg_autostart",
				Severity:    sev,
				Title:       "Suspicious command in XDG autostart entry",
				Detail:      fmt.Sprintf("The autostart entry %q contains %q in its Exec= line, which is associated with downloading or executing arbitrary code at login.", entryName, pattern),
				Evidence:    fmt.Sprintf("path: %s, Exec: %s", path, execLine),
				Location:    path,
				Remediation: fmt.Sprintf("Remove or disable the autostart entry %s. Investigate how it was created.", path),
			})
			break // one finding per file for exec patterns
		}
	}

	// Check for execution from /tmp, /dev/shm, or other writable dirs.
	for _, suspPath := range suspiciousExecPaths {
		if strings.HasPrefix(binary, suspPath) {
			sev := scanner.SevCritical
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("xdg_autostart", path, "exec from writable dir"),
				Scanner:     "xdg_autostart",
				Severity:    sev,
				Title:       "XDG autostart entry executes binary from world-writable directory",
				Detail:      fmt.Sprintf("The autostart entry %q runs a binary from %s (%s), a world-writable directory commonly used for staging malware.", entryName, suspPath, binary),
				Evidence:    fmt.Sprintf("path: %s, Exec: %s", path, execLine),
				Location:    path,
				Remediation: fmt.Sprintf("Remove or disable the autostart entry %s. Investigate the binary at %s.", path, binary),
			})
			break
		}
	}

	// If no critical finding yet, check whether the binary is owned by any package.
	if len(findings) == 0 {
		if binary != "" && !isPackageOwned(binary) {
			sev := scanner.SevHigh
			if isRecent {
				sev = scanner.SevCritical
			}
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("xdg_autostart", path, "unknown autostart entry: "+entryName),
				Scanner:     "xdg_autostart",
				Severity:    sev,
				Title:       "Unknown autostart entry: " + entryName,
				Detail:      fmt.Sprintf("The autostart entry %q runs %q, which is not owned by any installed package according to dpkg. Unpackaged binaries in autostart are a common persistence technique.", entryName, binary),
				Evidence:    fmt.Sprintf("path: %s, binary: %s, recently_created: %v", path, binary, isRecent),
				Location:    path,
				Remediation: fmt.Sprintf("Verify the binary %q is legitimate. If not, remove the autostart file %s.", binary, path),
			})
		}
	} else if isRecent {
		// Escalate severity of existing findings if file is recent.
		for i := range findings {
			if findings[i].Severity < scanner.SevCritical {
				findings[i].Severity = scanner.SevCritical
			}
		}
	}

	return findings
}

// isPackageOwned checks whether the given binary path is owned by a dpkg package.
// Returns true if dpkg confirms ownership, or if dpkg is unavailable (to avoid
// false positives in non-Debian environments).
func isPackageOwned(binary string) bool {
	// Resolve the binary to an absolute path if needed.
	absPath := binary
	if !filepath.IsAbs(binary) {
		resolved, err := exec.LookPath(binary)
		if err != nil {
			// Cannot resolve — treat as unpackaged.
			return false
		}
		absPath = resolved
	}

	dpkgPath, err := exec.LookPath("dpkg")
	if err != nil {
		// dpkg not available — cannot determine ownership; assume legitimate
		// to avoid false positives on non-Debian systems.
		return true
	}

	cmd := exec.Command(dpkgPath, "-S", absPath)
	out, err := cmd.Output()
	if err != nil {
		// dpkg -S returns non-zero when the file is not owned by any package.
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}
