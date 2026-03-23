package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// criticalLogFiles is the list of auth and syslog candidates to check.
// Each inner slice represents alternatives — the first one found wins.
var criticalLogCandidates = [][]string{
	{"/var/log/auth.log", "/var/log/secure"},
	{"/var/log/syslog", "/var/log/messages"},
}

// loggingServiceNames are the process names looked up under /proc/*/comm.
var loggingServiceNames = map[string]bool{
	"rsyslogd":          true,
	"syslogd":           true,
	"syslog-ng":         true,
	"systemd-journald":  true,
}

// maxTailLines is how many trailing lines of a log file are examined.
const maxTailLines = 1000

// LogsScanner checks system log files for tampering, unexpected gaps, and
// suspicious entries that may indicate a compromise.
type LogsScanner struct {
	// procPath can be overridden in tests.
	procPath string
	// authLogPath overrides the default auth log candidate search when non-empty.
	authLogPath string
}

// NewLogsScanner creates a new LogsScanner.
func NewLogsScanner() *LogsScanner {
	return &LogsScanner{procPath: "/proc"}
}

// SetProcPath overrides the /proc path (for testing).
func (s *LogsScanner) SetProcPath(path string) { s.procPath = path }

// SetAuthLogPath overrides the auth log path search (for testing).
func (s *LogsScanner) SetAuthLogPath(path string) { s.authLogPath = path }

func (s *LogsScanner) Name() string            { return "logs" }
func (s *LogsScanner) Category() string        { return "system" }
func (s *LogsScanner) RequiresRoot() bool      { return false }
func (s *LogsScanner) RequiredTools() []string { return nil }
func (s *LogsScanner) OptionalTools() []string { return nil }
func (s *LogsScanner) Available() bool         { return true }
func (s *LogsScanner) Description() string {
	return "Checks system logs (/var/log) for tampering indicators, unexpected gaps, and suspicious authentication failure patterns."
}

// Scan runs all log-analysis checks and returns the aggregated findings.
func (s *LogsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	var authLog string

	if s.authLogPath != "" {
		// Test mode: operate only on the injected auth log path.
		authLog = s.authLogPath
		findings = append(findings, s.checkSingleLog(authLog)...)
	} else {
		// 1. Presence and size of critical log files.
		presentLogs, presenceFindings := s.checkCriticalLogs()
		findings = append(findings, presenceFindings...)

		// 2. Timestamp gap detection (uses auth.log / secure).
		authLog = firstPresent(presentLogs[0])
	}

	if authLog != "" {
		findings = append(findings, s.checkTimestampGaps(authLog)...)
		// 4. Failed SSH login spike detection.
		findings = append(findings, s.checkBruteForce(authLog)...)
		// 5. Log file permissions.
		findings = append(findings, s.checkLogPermissions(authLog)...)
	}

	// 3. Logging service status.
	findings = append(findings, s.checkLoggingService()...)

	return findings, nil
}

// checkSingleLog checks existence and size of a single log path (used in tests).
func (s *LogsScanner) checkSingleLog(path string) []scanner.Finding {
	info, err := os.Stat(path)
	if err != nil {
		base := logBaseName(path)
		return []scanner.Finding{
			{
				ID:          scanner.GenerateFindingID("logs", path, "missing log file"),
				Scanner:     "logs",
				Severity:    scanner.SevCritical,
				Title:       "Critical log file is missing",
				Detail:      fmt.Sprintf("%s is missing — possible log tampering.", base),
				Evidence:    fmt.Sprintf("path not found: %s", path),
				Location:    path,
				Remediation: "Ensure the logging service is running and writing to " + path,
			},
		}
	}
	if info.Size() == 0 {
		base := logBaseName(path)
		return []scanner.Finding{
			{
				ID:          scanner.GenerateFindingID("logs", path, "empty log file"),
				Scanner:     "logs",
				Severity:    scanner.SevCritical,
				Title:       "Critical log file is empty",
				Detail:      fmt.Sprintf("%s is empty — possible truncation or log tampering.", base),
				Evidence:    fmt.Sprintf("path: %s, size: 0 bytes", path),
				Location:    path,
				Remediation: fmt.Sprintf("Investigate why %s is empty. Check for recent truncation.", base),
			},
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 1: missing / empty critical log files
// ---------------------------------------------------------------------------

// checkCriticalLogs verifies that the expected log files exist and are
// non-empty. It returns the set of present log path candidates (indexed by
// criticalLogCandidates position) alongside any findings.
func (s *LogsScanner) checkCriticalLogs() (presentLogs [][]string, findings []scanner.Finding) {
	presentLogs = make([][]string, len(criticalLogCandidates))

	for i, candidates := range criticalLogCandidates {
		found := false
		for _, path := range candidates {
			info, err := os.Stat(path)
			if err != nil {
				// File does not exist — continue to next candidate.
				continue
			}
			found = true
			presentLogs[i] = append(presentLogs[i], path)

			if info.Size() == 0 {
				base := logBaseName(path)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("logs", path, "empty log file"),
					Scanner:     "logs",
					Severity:    scanner.SevCritical,
					Title:       "Critical log file is empty",
					Detail:      fmt.Sprintf("%s is empty — possible truncation or log tampering.", base),
					Evidence:    fmt.Sprintf("path: %s, size: 0 bytes", path),
					Location:    path,
					Remediation: fmt.Sprintf("Investigate why %s is empty. Check for recent truncation with 'last', 'who', or audit logs.", base),
				})
			}
		}

		if !found {
			// Report the first candidate name in the finding.
			primary := candidates[0]
			base := logBaseName(primary)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("logs", primary, "missing log file"),
				Scanner:     "logs",
				Severity:    scanner.SevCritical,
				Title:       "Critical log file is missing",
				Detail:      fmt.Sprintf("%s is missing — possible log tampering.", base),
				Evidence:    fmt.Sprintf("candidates checked: %s", strings.Join(candidates, ", ")),
				Location:    primary,
				Remediation: fmt.Sprintf("Ensure the logging service is running and writing to %s. Check for tampering.", primary),
			})
		}
	}

	return presentLogs, findings
}

// ---------------------------------------------------------------------------
// Check 2: timestamp gaps in auth.log
// ---------------------------------------------------------------------------

// checkTimestampGaps reads the last maxTailLines lines of path and looks for
// consecutive timestamp gaps larger than 1 hour.
func (s *LogsScanner) checkTimestampGaps(path string) []scanner.Finding {
	lines, err := tailLines(path, maxTailLines)
	if err != nil {
		return nil
	}

	var findings []scanner.Finding
	var prev time.Time
	year := time.Now().Year()

	for _, line := range lines {
		ts, ok := parseSyslogTimestamp(line, year)
		if !ok {
			continue
		}
		if !prev.IsZero() && ts.Sub(prev) > time.Hour {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("logs", path, "timestamp gap at "+ts.String()),
				Scanner:     "logs",
				Severity:    scanner.SevHigh,
				Title:       "Suspicious gap in log timestamps",
				Detail:      fmt.Sprintf("A gap of %s was detected in %s around %s — possible log deletion or tampering.", ts.Sub(prev).Round(time.Minute), logBaseName(path), ts.Format("Jan 02 15:04")),
				Evidence:    fmt.Sprintf("previous entry: %s, next entry: %s", prev.Format("Jan 02 15:04:05"), ts.Format("Jan 02 15:04:05")),
				Location:    path,
				Remediation: "Investigate log rotation configuration and audit trail for unauthorized modifications.",
			})
		}
		prev = ts
	}

	return findings
}

// syslogLayouts are tried in order when parsing a syslog timestamp prefix.
// Three forms appear in the wild:
//   - space-padded single-digit day: "Jan  2 15:04:05"
//   - double-digit day (one space):  "Jan 23 15:04:05"  → parsed with "Jan _2 ..." layout
//   - zero-padded day:               "Jan 02 15:04:05"
var syslogLayouts = []string{
	"Jan  2 15:04:05", // space-padded single-digit (two spaces)
	"Jan 02 15:04:05", // zero-padded
	"Jan _2 15:04:05", // Go's space-pad shorthand (handles both)
}

// parseSyslogTimestamp extracts a time.Time from a syslog-format line.
// It handles both single-digit and double-digit day fields.
func parseSyslogTimestamp(line string, year int) (time.Time, bool) {
	if len(line) < 15 {
		return time.Time{}, false
	}
	// Standard syslog: "Jan  2 15:04:05 hostname ..."
	//               or "Jan 23 15:04:05 hostname ..."
	candidate := line[:15]
	for _, layout := range syslogLayouts {
		t, err := time.Parse(layout, candidate)
		if err == nil {
			// Attach the current year (syslog omits year).
			t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			return t, true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// Check 3: logging service status
// ---------------------------------------------------------------------------

// checkLoggingService looks for known syslog/journal daemons in /proc.
func (s *LogsScanner) checkLoggingService() []scanner.Finding {
	entries, err := os.ReadDir(s.procPath)
	if err != nil {
		// Cannot read /proc — skip this check.
		return nil
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		commPath := fmt.Sprintf("%s/%s/comm", s.procPath, e.Name())
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if loggingServiceNames[name] {
			return nil // at least one logging service found
		}
	}

	return []scanner.Finding{
		{
			ID:          scanner.GenerateFindingID("logs", s.procPath, "no logging service"),
			Scanner:     "logs",
			Severity:    scanner.SevHigh,
			Title:       "No logging service detected",
			Detail:      "Neither rsyslog, syslog-ng, nor systemd-journald appears to be running. System events may not be recorded.",
			Evidence:    "No matching process found in " + s.procPath,
			Location:    s.procPath,
			Remediation: "Start the appropriate logging service: 'systemctl start rsyslog' or 'systemctl start systemd-journald'.",
		},
	}
}

// ---------------------------------------------------------------------------
// Check 4: brute-force detection
// ---------------------------------------------------------------------------

// checkBruteForce counts failed authentication lines in path.
func (s *LogsScanner) checkBruteForce(path string) []scanner.Finding {
	lines, err := tailLines(path, maxTailLines)
	if err != nil {
		return nil
	}

	count := 0
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure") {
			count++
		}
	}

	if count == 0 {
		return nil
	}

	var sev scanner.Severity
	var title, detail string

	switch {
	case count > 200:
		sev = scanner.SevHigh
		title = "High-volume authentication failures detected"
		detail = fmt.Sprintf("Possible brute force: %d failed logins in the last %d lines of %s.", count, maxTailLines, logBaseName(path))
	case count > 50:
		sev = scanner.SevMedium
		title = "Elevated authentication failures detected"
		detail = fmt.Sprintf("Possible brute force: %d failed logins in the last %d lines of %s.", count, maxTailLines, logBaseName(path))
	default:
		return nil
	}

	return []scanner.Finding{
		{
			ID:          scanner.GenerateFindingID("logs", path, "brute force attempt"),
			Scanner:     "logs",
			Severity:    sev,
			Title:       title,
			Detail:      detail,
			Evidence:    fmt.Sprintf("failed login count: %d in last %d lines", count, maxTailLines),
			Location:    path,
			Remediation: "Review /var/log/auth.log for source IPs and consider installing fail2ban or tightening SSH access controls.",
		},
	}
}

// ---------------------------------------------------------------------------
// Check 5: log file permissions
// ---------------------------------------------------------------------------

// checkLogPermissions flags log files that are world-readable.
func (s *LogsScanner) checkLogPermissions(path string) []scanner.Finding {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	mode := info.Mode().Perm()
	// World-readable: bit 0o004
	if mode&0o004 != 0 {
		return []scanner.Finding{
			{
				ID:          scanner.GenerateFindingID("logs", path, "world-readable log"),
				Scanner:     "logs",
				Severity:    scanner.SevMedium,
				Title:       "Log file is world-readable",
				Detail:      fmt.Sprintf("%s has permissions %04o — world-readable log files may expose sensitive authentication data.", logBaseName(path), mode),
				Evidence:    fmt.Sprintf("path: %s, permissions: %04o", path, mode),
				Location:    path,
				Remediation: fmt.Sprintf("Restrict permissions: 'chmod 0640 %s && chown root:adm %s'", path, path),
			},
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// tailLines returns up to n trailing lines from path.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Use a ring buffer to keep the last n lines without loading the whole file.
	ring := make([]string, n)
	pos := 0
	count := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ring[pos%n] = sc.Text()
		pos++
		if count < n {
			count++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, nil
	}

	// Reconstruct in order.
	result := make([]string, count)
	start := 0
	if pos > n {
		start = pos % n
	}
	for i := 0; i < count; i++ {
		result[i] = ring[(start+i)%n]
	}
	return result, nil
}

// firstPresent returns the first non-empty string from candidates.
func firstPresent(candidates []string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return ""
}

// logBaseName extracts just the filename from an absolute log path.
func logBaseName(path string) string {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}
