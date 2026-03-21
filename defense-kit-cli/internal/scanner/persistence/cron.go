package persistence

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

// cronPattern describes a suspicious pattern to match in cron entries.
type cronPattern struct {
	re          *regexp.Regexp
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

var cronPatterns = []cronPattern{
	{
		re:          regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh|python|perl|ruby)`),
		title:       "Pipe-to-shell execution in cron",
		severity:    scanner.SevCritical,
		detail:      "Downloading and piping code directly to a shell interpreter is a common attack vector for cron-based persistence.",
		remediation: "Remove the pipe-to-shell construct. Download files explicitly and verify checksums before executing.",
	},
	{
		re:          regexp.MustCompile(`(?i)(bash|sh)\s+-i\s+>&\s*/dev/tcp/`),
		title:       "Reverse shell via /dev/tcp in cron",
		severity:    scanner.SevCritical,
		detail:      "A cron entry establishing a reverse shell via /dev/tcp provides persistent remote access to an attacker.",
		remediation: "Remove the cron entry immediately and investigate the source of the modification.",
	},
	{
		re:          regexp.MustCompile(`/dev/tcp/`),
		title:       "Bash /dev/tcp usage in cron",
		severity:    scanner.SevCritical,
		detail:      "Use of /dev/tcp in cron is a common technique to establish persistent reverse shells.",
		remediation: "Remove the /dev/tcp construct from the cron entry.",
	},
	{
		re:          regexp.MustCompile(`(?i)base64\s+-d`),
		title:       "Base64-decoded execution in cron",
		severity:    scanner.SevHigh,
		detail:      "Decoding and executing base64-encoded payloads in cron is commonly used to hide malicious commands.",
		remediation: "Remove the base64 decode construct and audit the encoded payload.",
	},
	{
		re:          regexp.MustCompile(`(?i)eval\s+.*base64`),
		title:       "Obfuscated code via base64 eval in cron",
		severity:    scanner.SevCritical,
		detail:      "Using eval with base64-decoded content is commonly used to hide malicious code in cron jobs.",
		remediation: "Remove the eval/base64 construct and audit the encoded payload.",
	},
	{
		re:          regexp.MustCompile(`(?i)\b(xterm|ncat|nc|netcat)\s+-e\s+`),
		title:       "Netcat/xterm reverse shell in cron",
		severity:    scanner.SevCritical,
		detail:      "Using netcat or xterm with -e in a cron entry is a standard reverse-shell persistence technique.",
		remediation: "Remove the cron entry immediately and investigate how it was added.",
	},
	{
		re:          regexp.MustCompile(`(?i)/(tmp|dev/shm)/\S+`),
		title:       "Executable in world-writable directory in cron",
		severity:    scanner.SevHigh,
		detail:      "Running executables from /tmp or /dev/shm in cron is suspicious; these directories are world-writable and often used for staging malware.",
		remediation: "Move legitimate scripts to a protected directory (e.g., /usr/local/bin) and update the cron entry.",
	},
}

// cronFilePaths lists the cron file locations to scan.
var cronFilePaths = []string{
	"/etc/crontab",
}

// cronGlobPatterns lists glob patterns for additional cron directories.
var cronGlobPatterns = []string{
	"/var/spool/cron/crontabs/*",
	"/etc/cron.d/*",
}

// CronScanner scans cron files for suspicious scheduled entries.
type CronScanner struct{}

// NewCronScanner creates a new CronScanner.
func NewCronScanner() *CronScanner {
	return &CronScanner{}
}

func (s *CronScanner) Name() string           { return "cron" }
func (s *CronScanner) Category() string       { return "persistence" }
func (s *CronScanner) RequiresRoot() bool     { return true }
func (s *CronScanner) RequiredTools() []string { return nil }
func (s *CronScanner) OptionalTools() []string { return nil }
func (s *CronScanner) Available() bool        { return true }
func (s *CronScanner) Description() string {
	return "Scans cron files (/etc/crontab, /etc/cron.d/*, /var/spool/cron/crontabs/*) for suspicious scheduled entries including pipe-to-shell, reverse shells, base64 obfuscation, and executables in world-writable directories."
}

// Scan inspects cron files for suspicious entries.
func (s *CronScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var paths []string

	// Add static cron files.
	paths = append(paths, cronFilePaths...)

	// Expand glob patterns.
	for _, pattern := range cronGlobPatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			// Invalid glob pattern — skip.
			continue
		}
		paths = append(paths, matches...)
	}

	var findings []scanner.Finding
	for _, path := range paths {
		ff, err := scanCronFile(path)
		if err != nil {
			// File not found or unreadable — skip silently.
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// scanCronFile scans a single cron file and returns findings.
func scanCronFile(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding
	lineNum := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, p := range cronPatterns {
			if p.re.MatchString(trimmed) {
				location := fmt.Sprintf("%s:%d", path, lineNum)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("cron", location, p.title),
					Scanner:     "cron",
					Severity:    p.severity,
					Title:       p.title,
					Detail:      p.detail,
					Evidence:    trimmed,
					Location:    location,
					Remediation: p.remediation,
				})
			}
		}
	}
	return findings, sc.Err()
}
