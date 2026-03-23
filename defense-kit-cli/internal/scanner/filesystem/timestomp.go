package filesystem

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// TimestompScanner detects files whose timestamps have been manipulated to
// hide recent modifications (timestomping).
type TimestompScanner struct {
	// scanDirs are the directories to inspect for timestomping.
	scanDirs []string
}

// NewTimestompScanner creates a new TimestompScanner.
func NewTimestompScanner() *TimestompScanner {
	return &TimestompScanner{
		scanDirs: []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"},
	}
}

func (s *TimestompScanner) Name() string           { return "timestomp" }
func (s *TimestompScanner) Category() string       { return "filesystem" }
func (s *TimestompScanner) RequiresRoot() bool     { return false }
func (s *TimestompScanner) RequiredTools() []string { return nil }
func (s *TimestompScanner) OptionalTools() []string { return nil }
func (s *TimestompScanner) Available() bool        { return true }
func (s *TimestompScanner) Description() string {
	return "Detects files whose timestamps have been manipulated to hide recent modifications (timestomping)."
}

// CheckTimestomp inspects a single file for timestamp anomalies. Exported for
// testing with synthetic inputs.
func CheckTimestomp(path string, info os.FileInfo) []scanner.Finding {
	return checkTimestomp(path, info)
}

// checkTimestomp inspects a single file for timestamp anomalies.
func checkTimestomp(path string, info os.FileInfo) []scanner.Finding {
	var findings []scanner.Finding
	now := time.Now()

	mtime := info.ModTime()

	// mtime in the future is always suspicious (CRITICAL).
	if mtime.After(now.Add(5 * time.Minute)) {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("timestomp", path, "mtime in the future"),
			Scanner:  "timestomp",
			Severity: scanner.SevCritical,
			Title:    "File modification time is in the future",
			Detail: fmt.Sprintf(
				"File %q has a modification time (%s) that is in the future (current time: %s). This is a strong indicator of timestamp manipulation.",
				path, mtime.Format(time.RFC3339), now.Format(time.RFC3339),
			),
			Evidence:    fmt.Sprintf("mtime: %s", mtime.Format(time.RFC3339)),
			Location:    path,
			Remediation: fmt.Sprintf("Investigate the file %s and verify its integrity. Check system logs for who modified it.", path),
		})
		return findings // future mtime supersedes the mtime>ctime check
	}

	// On Linux, compare mtime vs ctime via syscall.Stat_t.
	// If mtime is older than ctime, the file metadata (ctime) was updated more
	// recently than the declared mtime — a hallmark of timestomping.
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return findings
	}

	ctime := time.Unix(sys.Ctim.Sec, sys.Ctim.Nsec)

	// A legitimate file has mtime <= ctime (metadata update always updates ctime).
	// If mtime < ctime by more than 1 second, the mtime was likely set artificially.
	if mtime.Add(time.Second).Before(ctime) {
		findings = append(findings, scanner.Finding{
			ID:      scanner.GenerateFindingID("timestomp", path, "mtime older than ctime"),
			Scanner: "timestomp",
			Severity: scanner.SevHigh,
			Title:   "File mtime is older than ctime (possible timestomping)",
			Detail: fmt.Sprintf(
				"File %q has mtime (%s) that is older than ctime (%s). On Linux, ctime is updated whenever a file is modified; an mtime older than ctime indicates the mtime may have been set backwards to hide a recent modification.",
				path, mtime.Format(time.RFC3339), ctime.Format(time.RFC3339),
			),
			Evidence:    fmt.Sprintf("mtime: %s, ctime: %s", mtime.Format(time.RFC3339), ctime.Format(time.RFC3339)),
			Location:    path,
			Remediation: fmt.Sprintf("Verify the integrity of %s using a package manager (e.g., dpkg -V or rpm -V). Reinstall the package if the file has been tampered with.", path),
			References: []string{
				"https://attack.mitre.org/techniques/T1070/006/",
			},
		})
	}

	return findings
}

// Scan inspects system binary directories for timestamp anomalies.
func (s *TimestompScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	for _, dir := range s.scanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Directory does not exist or is not readable — skip gracefully.
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}
			ff := checkTimestomp(path, info)
			findings = append(findings, ff...)
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}
