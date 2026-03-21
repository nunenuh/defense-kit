package process

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// processPattern describes a suspicious pattern to match against a process cmdline.
type processPattern struct {
	re          *regexp.Regexp
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

var processPatterns = []processPattern{
	{
		re:          regexp.MustCompile(`bash\s+-i\s+>&?\s*/dev/tcp/`),
		title:       "Reverse shell via bash /dev/tcp",
		severity:    scanner.SevCritical,
		detail:      "A running process is using bash's /dev/tcp pseudo-device to establish a reverse shell connection.",
		remediation: "Kill the process immediately, investigate how it was launched, and audit for persistence mechanisms.",
	},
	{
		re:          regexp.MustCompile(`/dev/tcp/`),
		title:       "Process using /dev/tcp",
		severity:    scanner.SevCritical,
		detail:      "A running process references /dev/tcp, which is commonly used to establish reverse shells.",
		remediation: "Kill the process, investigate its origin, and check for persistence mechanisms.",
	},
	{
		re:          regexp.MustCompile(`(?i)\b(xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer|t-rex)\b`),
		title:       "Cryptocurrency miner detected",
		severity:    scanner.SevCritical,
		detail:      "A known cryptocurrency mining binary is running. This indicates unauthorized resource usage and likely a compromise.",
		remediation: "Kill the process, remove the binary, and audit the system for the initial access vector.",
	},
	{
		re:          regexp.MustCompile(`stratum\+tcp://`),
		title:       "Stratum mining protocol in use",
		severity:    scanner.SevCritical,
		detail:      "A process is connecting to a Stratum mining pool, indicating active cryptocurrency mining.",
		remediation: "Kill the process, remove the binary, and investigate the compromise.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bnc(\.traditional)?\b.*-[el]`),
		title:       "Netcat listener or reverse shell",
		severity:    scanner.SevCritical,
		detail:      "A netcat process is running with -e or -l flags, which are commonly used for reverse shells or persistent backdoors.",
		remediation: "Kill the process and investigate how it was launched. Check for cron or systemd persistence.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bncat\b.*-(e|-exec)`),
		title:       "Ncat with exec flag",
		severity:    scanner.SevCritical,
		detail:      "ncat with --exec/-e is running, which can serve as a reverse shell or backdoor.",
		remediation: "Kill the process and audit for persistence mechanisms.",
	},
}

// suspiciousPathPatterns matches processes launched from world-writable or suspicious directories.
var suspiciousPathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/tmp/`),
	regexp.MustCompile(`^/dev/shm/`),
}

// SuspiciousScanner reads /proc to detect suspicious running processes.
type SuspiciousScanner struct {
	// procRoot is the root of the proc filesystem; overrideable in tests.
	procRoot string
}

// NewSuspiciousScanner creates a new SuspiciousScanner.
func NewSuspiciousScanner() *SuspiciousScanner {
	return &SuspiciousScanner{procRoot: "/proc"}
}

func (s *SuspiciousScanner) Name() string           { return "processes" }
func (s *SuspiciousScanner) Category() string       { return "process" }
func (s *SuspiciousScanner) RequiresRoot() bool     { return false }
func (s *SuspiciousScanner) RequiredTools() []string { return nil }
func (s *SuspiciousScanner) OptionalTools() []string { return nil }
func (s *SuspiciousScanner) Available() bool        { return true }
func (s *SuspiciousScanner) Description() string {
	return "Reads /proc/*/cmdline and /proc/*/status to detect suspicious running processes including reverse shells, cryptocurrency miners, netcat listeners, and processes executing from world-writable directories."
}

// Scan inspects /proc for suspicious running processes.
func (s *SuspiciousScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		return nil, fmt.Errorf("processes: cannot read %s: %w", s.procRoot, err)
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only numeric directories are process entries.
		pid := entry.Name()
		if !isNumeric(pid) {
			continue
		}

		cmdline, err := readCmdline(filepath.Join(s.procRoot, pid, "cmdline"))
		if err != nil || cmdline == "" {
			continue
		}

		exe := readExeLink(filepath.Join(s.procRoot, pid, "exe"))

		ff := s.checkProcess(pid, cmdline, exe)
		findings = append(findings, ff...)
	}
	return findings, nil
}

// checkProcess inspects a single process cmdline and exe path for suspicious indicators.
func (s *SuspiciousScanner) checkProcess(pid, cmdline, exe string) []scanner.Finding {
	var findings []scanner.Finding

	// Check cmdline against known suspicious patterns.
	for _, p := range processPatterns {
		if p.re.MatchString(cmdline) {
			location := fmt.Sprintf("/proc/%s/cmdline", pid)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("processes", location, p.title),
				Scanner:     "processes",
				Severity:    p.severity,
				Title:       p.title,
				Detail:      p.detail,
				Evidence:    cmdline,
				Location:    location,
				Remediation: p.remediation,
				Metadata:    map[string]string{"pid": pid},
			})
		}
	}

	// Check whether the executable path is in a world-writable directory.
	exePath := exe
	if exePath == "" {
		// Fall back to first token in cmdline.
		parts := strings.SplitN(cmdline, " ", 2)
		exePath = parts[0]
	}
	for _, re := range suspiciousPathPatterns {
		if re.MatchString(exePath) {
			location := fmt.Sprintf("/proc/%s/exe", pid)
			title := fmt.Sprintf("Process executing from world-writable directory: %s", exePath)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("processes", location, title),
				Scanner:     "processes",
				Severity:    scanner.SevHigh,
				Title:       "Process executing from world-writable directory",
				Detail:      fmt.Sprintf("Process PID %s is running from %q, a world-writable directory commonly used for staging malware.", pid, exePath),
				Evidence:    exePath,
				Location:    location,
				Remediation: "Kill the process, remove the binary from the world-writable location, and investigate its origin.",
				Metadata:    map[string]string{"pid": pid, "exe": exePath},
			})
			break
		}
	}

	return findings
}

// readCmdline reads and decodes a /proc/<pid>/cmdline file (NUL-separated args).
func readCmdline(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// /proc/<pid>/cmdline uses NUL bytes as argument separators.
	return string(bytes.ReplaceAll(data, []byte{0}, []byte{' '})), nil
}

// readExeLink resolves the /proc/<pid>/exe symlink, returning "" on failure.
func readExeLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

// readProcStatus reads a field from /proc/<pid>/status. Returns "" on failure.
func readProcStatus(path, field string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	prefix := field + ":"
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

// isNumeric reports whether s contains only ASCII digits.
func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
