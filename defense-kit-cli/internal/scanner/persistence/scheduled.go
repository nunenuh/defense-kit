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

// ScheduledScanner checks for suspicious at(1) jobs and other scheduled tasks.
type ScheduledScanner struct {
	// atSpoolDir is the directory containing at job files.
	atSpoolDir string
}

// NewScheduledScanner creates a new ScheduledScanner.
func NewScheduledScanner() *ScheduledScanner {
	return &ScheduledScanner{
		atSpoolDir: "/var/spool/at",
	}
}

// NewScheduledScannerWithDir creates a ScheduledScanner with a custom at spool
// directory (used in tests).
func NewScheduledScannerWithDir(atSpoolDir string) *ScheduledScanner {
	return &ScheduledScanner{atSpoolDir: atSpoolDir}
}

func (s *ScheduledScanner) Name() string           { return "scheduled" }
func (s *ScheduledScanner) Category() string       { return "persistence" }
func (s *ScheduledScanner) RequiresRoot() bool     { return true }
func (s *ScheduledScanner) RequiredTools() []string { return nil }
func (s *ScheduledScanner) OptionalTools() []string { return nil }
func (s *ScheduledScanner) Available() bool        { return true }
func (s *ScheduledScanner) Description() string {
	return "Scans at(1) job queues and other scheduled task mechanisms for suspicious persistence entries."
}

// Scan checks scheduled task queues (at jobs, systemd timers) for suspicious entries.
func (s *ScheduledScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.checkAtQueue()...)
	findings = append(findings, s.checkAtSpoolDir()...)
	findings = append(findings, checkSystemdTimers()...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkAtQueue runs atq and checks for pending at jobs.
func (s *ScheduledScanner) checkAtQueue() []scanner.Finding {
	atqPath, err := exec.LookPath("atq")
	if err != nil {
		// atq not available — skip gracefully.
		return nil
	}

	out, err := exec.Command(atqPath).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	return parseAtqOutput(string(out))
}

// ParseAtqOutput parses the output of atq and returns findings for pending
// at jobs. Exported for testing with synthetic input.
func ParseAtqOutput(output string) []scanner.Finding {
	return parseAtqOutput(output)
}

// parseAtqOutput parses atq output.
// Each line has the form: <jobnum>\t<date> <time> <queue> <user>
func parseAtqOutput(output string) []scanner.Finding {
	var findings []scanner.Finding
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("scheduled", "/var/spool/at", "pending at job: "+line),
			Scanner:  "scheduled",
			Severity: scanner.SevMedium,
			Title:    "Pending at(1) job found",
			Detail:   fmt.Sprintf("A pending at job was found in the at queue: %q. At jobs are commonly used for persistence as they execute scheduled commands and may not be easily visible.", line),
			Evidence:  line,
			Location:  "/var/spool/at",
			Remediation: "Review the at job with `at -c <jobnum>` and remove it with `atrm <jobnum>` if not legitimate.",
		})
	}
	return findings
}

// checkAtSpoolDir inspects /var/spool/at for at job files.
func (s *ScheduledScanner) checkAtSpoolDir() []scanner.Finding {
	entries, err := os.ReadDir(s.atSpoolDir)
	if err != nil {
		return nil
	}

	var findings []scanner.Finding
	// Recent threshold: files created within the last 7 days are more interesting.
	recentThreshold := time.Now().Add(-7 * 24 * time.Hour)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// At job files typically start with 'a', 'b', 'c', or 'e' followed by hex digits.
		if len(name) < 2 {
			continue
		}
		path := filepath.Join(s.atSpoolDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		sev := scanner.SevMedium
		timeDesc := ""
		if info.ModTime().After(recentThreshold) {
			timeDesc = " (created within the last 7 days)"
		}

		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("scheduled", path, "at job file"),
			Scanner:  "scheduled",
			Severity: sev,
			Title:    "At job file found in spool directory",
			Detail:   fmt.Sprintf("At job file %q found in %s%s. At jobs execute commands at scheduled times and can be used for persistence.", path, s.atSpoolDir, timeDesc),
			Evidence:  fmt.Sprintf("path: %s, mtime: %s", path, info.ModTime().Format(time.RFC3339)),
			Location:  path,
			Remediation: "Inspect the at job file and remove it with `atrm` if not legitimate.",
		})
	}
	return findings
}

// checkSystemdTimers checks systemd timers for recently created ones.
func checkSystemdTimers() []scanner.Finding {
	// Look for timer unit files in common systemd directories.
	timerDirs := []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/usr/local/lib/systemd/system",
	}

	var findings []scanner.Finding
	recentThreshold := time.Now().Add(-7 * 24 * time.Hour)

	for _, dir := range timerDirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.timer"))
		if err != nil {
			continue
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			if info.ModTime().After(recentThreshold) {
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID("scheduled", path, "recently created systemd timer"),
					Scanner:  "scheduled",
					Severity: scanner.SevMedium,
					Title:    "Recently created systemd timer unit",
					Detail: fmt.Sprintf(
						"Systemd timer unit %q was created or modified within the last 7 days (%s). Recently added timer units may indicate unauthorized persistence.",
						path, info.ModTime().Format(time.RFC3339),
					),
					Evidence:    fmt.Sprintf("path: %s, mtime: %s", path, info.ModTime().Format(time.RFC3339)),
					Location:    path,
					Remediation: fmt.Sprintf("Review the timer unit: `systemctl cat %s`. Disable if not legitimate: `systemctl disable --now %s`.", filepath.Base(path), filepath.Base(path)),
				})
			}
		}
	}
	return findings
}
