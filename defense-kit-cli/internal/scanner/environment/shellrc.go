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

// shellRCPattern describes a suspicious pattern to match in shell RC files.
type shellRCPattern struct {
	re       *regexp.Regexp
	title    string
	severity scanner.Severity
	detail   string
	remediation string
}

var shellRCPatterns = []shellRCPattern{
	{
		re:          regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh)`),
		title:       "Pipe-to-shell execution",
		severity:    scanner.SevCritical,
		detail:      "Downloading and executing code directly from the internet is a common attack vector.",
		remediation: "Remove the pipe-to-shell construct and review what is being executed.",
	},
	{
		re:          regexp.MustCompile(`eval\s+.*base64`),
		title:       "Obfuscated code via base64 eval",
		severity:    scanner.SevCritical,
		detail:      "Using eval with base64-decoded content is commonly used to hide malicious code.",
		remediation: "Remove the eval/base64 construct and audit the encoded payload.",
	},
	{
		re:          regexp.MustCompile(`eval\s*\$\(`),
		title:       "Dynamic eval with command substitution",
		severity:    scanner.SevHigh,
		detail:      "eval with command substitution can execute arbitrary code.",
		remediation: "Avoid eval; refactor to use explicit function calls or variable assignments.",
	},
	{
		re:          regexp.MustCompile(`export\s+PATH=.*(/tmp/|/dev/shm/)`),
		title:       "PATH hijacking via /tmp or /dev/shm",
		severity:    scanner.SevHigh,
		detail:      "Adding world-writable directories to PATH enables binary hijacking.",
		remediation: "Remove /tmp and /dev/shm entries from PATH.",
	},
	{
		re:          regexp.MustCompile(`nc\s+-l`),
		title:       "Netcat listener",
		severity:    scanner.SevCritical,
		detail:      "A netcat listener in a shell RC file could establish a persistent backdoor.",
		remediation: "Remove the netcat listener command.",
	},
	{
		re:          regexp.MustCompile(`/dev/tcp/`),
		title:       "Bash /dev/tcp reverse shell",
		severity:    scanner.SevCritical,
		detail:      "Use of /dev/tcp is a common technique to establish reverse shells.",
		remediation: "Remove the /dev/tcp construct from the file.",
	},
	{
		re:          regexp.MustCompile(`PROMPT_COMMAND=.*(?:curl|wget)`),
		title:       "Data exfiltration via PROMPT_COMMAND",
		severity:    scanner.SevCritical,
		detail:      "Embedding curl/wget in PROMPT_COMMAND silently exfiltrates data on every prompt.",
		remediation: "Remove curl/wget from PROMPT_COMMAND.",
	},
}

// rcFileNames lists the shell RC files to scan within each target directory
// (or home directory by default).
var rcFileNames = []string{
	".bashrc",
	".bash_profile",
	".bash_login",
	".profile",
	".zshrc",
	".zprofile",
	".zlogin",
	".zshenv",
	".tcshrc",
	".cshrc",
	".kshrc",
}

// ShellRCScanner scans shell RC files for suspicious patterns.
type ShellRCScanner struct{}

// NewShellRCScanner creates a new ShellRCScanner.
func NewShellRCScanner() *ShellRCScanner {
	return &ShellRCScanner{}
}

func (s *ShellRCScanner) Name() string        { return "shell_rc" }
func (s *ShellRCScanner) Category() string    { return "environment" }
func (s *ShellRCScanner) RequiresRoot() bool  { return false }
func (s *ShellRCScanner) RequiredTools() []string { return nil }
func (s *ShellRCScanner) OptionalTools() []string { return nil }
func (s *ShellRCScanner) Available() bool     { return true }
func (s *ShellRCScanner) Description() string {
	return "Scans shell RC files (.bashrc, .zshrc, etc.) for suspicious patterns such as pipe-to-shell, obfuscated code, PATH hijacking, reverse shells, and data exfiltration."
}

// Scan inspects shell RC files in the provided target paths (or the user's home
// directory when no paths are specified).
func (s *ShellRCScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	dirs := opts.TargetPaths
	if len(dirs) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("shell_rc: cannot determine home directory: %w", err)
		}
		dirs = []string{home}
	}

	var findings []scanner.Finding
	for _, dir := range dirs {
		for _, name := range rcFileNames {
			path := filepath.Join(dir, name)
			ff, err := scanRCFile(path)
			if err != nil {
				// File not found or unreadable – skip silently.
				continue
			}
			findings = append(findings, ff...)
		}
	}
	return findings, nil
}

// scanRCFile scans a single RC file and returns findings.
func scanRCFile(path string) ([]scanner.Finding, error) {
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

		for _, p := range shellRCPatterns {
			if p.re.MatchString(trimmed) {
				location := fmt.Sprintf("%s:%d", path, lineNum)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("shell_rc", location, p.title),
					Scanner:     "shell_rc",
					Severity:    p.severity,
					Title:       p.title,
					Detail:      p.detail,
					Evidence:    trimmed,
					Location:    location,
					Remediation: p.remediation,
				})
				// One finding per line per pattern; continue checking other patterns.
			}
		}
	}
	return findings, sc.Err()
}
