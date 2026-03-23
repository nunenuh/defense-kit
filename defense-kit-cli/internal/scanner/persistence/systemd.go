package persistence

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// execStartFields lists the unit-file keys that carry executable paths.
var execStartFields = []string{
	"ExecStart=",
	"ExecStartPre=",
	"ExecStartPost=",
}

// writableStagingPrefixes are directories that are world-writable and
// commonly used to stage malware.
var writableStagingPrefixes = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
}

// suspiciousExecPatterns are regex checks applied to every ExecStart* value
// found in a service file. Each entry maps to a severity and description.
type execPattern struct {
	re          *regexp.Regexp
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

var suspiciousExecPatterns = []execPattern{
	{
		re:          regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh|python|perl|ruby)`),
		title:       "Pipe-to-shell execution in systemd service",
		severity:    scanner.SevCritical,
		detail:      "Downloading and piping code directly to a shell interpreter is a common attack vector for service-based persistence.",
		remediation: "Remove the pipe-to-shell construct. Download files explicitly and verify checksums before executing.",
	},
	{
		re:          regexp.MustCompile(`/dev/tcp/`),
		title:       "Bash /dev/tcp reverse-shell in systemd service",
		severity:    scanner.SevCritical,
		detail:      "Use of /dev/tcp in a service ExecStart is a common technique to establish a persistent reverse shell.",
		remediation: "Remove the unit file immediately and investigate how it was installed.",
	},
	{
		re:          regexp.MustCompile(`(?i)base64\s+-d`),
		title:       "Base64-decoded execution in systemd service",
		severity:    scanner.SevHigh,
		detail:      "Decoding and executing a base64-encoded payload in a service is commonly used to hide malicious commands.",
		remediation: "Remove the unit file and audit the encoded payload.",
	},
}

// SystemdScanner checks for suspicious systemd units, timers, and drop-ins.
type SystemdScanner struct{}

// NewSystemdScanner creates a new SystemdScanner.
func NewSystemdScanner() *SystemdScanner {
	return &SystemdScanner{}
}

func (s *SystemdScanner) Name() string            { return "systemd" }
func (s *SystemdScanner) Category() string        { return "persistence" }
func (s *SystemdScanner) RequiresRoot() bool      { return true }
func (s *SystemdScanner) RequiredTools() []string  { return nil }
func (s *SystemdScanner) OptionalTools() []string  { return []string{"dpkg"} }
func (s *SystemdScanner) Available() bool         { return true }
func (s *SystemdScanner) Description() string {
	return "Scans systemd unit files, timers, and drop-ins for suspicious persistence mechanisms including rogue services, drop-in overrides, and pipe-to-shell execution."
}

// Scan checks systemd units, timers, and drop-ins for suspicious entries.
func (s *SystemdScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	dpkgAvailable := isDpkgAvailable()

	// 1. User-level services and timers — one dir per home user.
	homeMatches, _ := filepath.Glob("/home/*")
	for _, homeDir := range homeMatches {
		userSystemdDir := filepath.Join(homeDir, ".config", "systemd", "user")
		ff := scanUserSystemdDir(userSystemdDir)
		findings = append(findings, ff...)
	}

	// 2. System service anomalies — /etc/systemd/system/*.service
	systemServiceMatches, _ := filepath.Glob("/etc/systemd/system/*.service")
	for _, path := range systemServiceMatches {
		ff := scanSystemService(path, dpkgAvailable)
		findings = append(findings, ff...)
	}

	// 3. Drop-in overrides — /etc/systemd/system/*.service.d/*.conf
	dropInMatches, _ := filepath.Glob("/etc/systemd/system/*.service.d/*.conf")
	for _, path := range dropInMatches {
		ff := scanDropIn(path)
		findings = append(findings, ff...)
	}

	// 4. System-level timers — /etc/systemd/system/*.timer
	systemTimerMatches, _ := filepath.Glob("/etc/systemd/system/*.timer")
	for _, path := range systemTimerMatches {
		ff := scanSystemdTimer(path, false)
		findings = append(findings, ff...)
	}

	return findings, nil
}

// scanUserSystemdDir scans a user-level systemd directory and returns findings.
func scanUserSystemdDir(dir string) []scanner.Finding {
	var findings []scanner.Finding

	serviceMatches, _ := filepath.Glob(filepath.Join(dir, "*.service"))
	for _, path := range serviceMatches {
		execLines := extractExecStartLines(path)
		name := filepath.Base(path)

		// Any user-level .service is at minimum MEDIUM on a server.
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("systemd", path, "User-level systemd service"),
			Scanner:     "systemd",
			Severity:    scanner.SevMedium,
			Title:       "User-level systemd service",
			Detail:      fmt.Sprintf("User-level service %q found at %s — unusual on servers, review carefully.", name, path),
			Evidence:    path,
			Location:    path,
			Remediation: "If this service is not intentional, remove the unit file and run `systemctl --user disable " + name + "`.",
		})

		// Run ExecStart content checks.
		for _, line := range execLines {
			findings = append(findings, checkExecLine(line, path, "systemd")...)
		}
	}

	timerMatches, _ := filepath.Glob(filepath.Join(dir, "*.timer"))
	for _, path := range timerMatches {
		findings = append(findings, scanSystemdTimer(path, true)...)
	}

	return findings
}

// scanSystemService scans a single system-level service file.
func scanSystemService(path string, dpkgAvailable bool) []scanner.Finding {
	var findings []scanner.Finding

	execLines := extractExecStartLines(path)

	// Check if the service is owned by a package (dpkg only).
	if dpkgAvailable && !isOwnedByPackage(path) {
		name := filepath.Base(path)
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("systemd", path, "Unknown systemd service not from any installed package"),
			Scanner:     "systemd",
			Severity:    scanner.SevHigh,
			Title:       fmt.Sprintf("Unknown systemd service: %s, not from any installed package", name),
			Detail:      fmt.Sprintf("Service file %s is not tracked by dpkg. It may have been manually installed by an attacker.", path),
			Evidence:    path,
			Location:    path,
			Remediation: "Investigate the origin of this service file. If not intentional, disable and remove it.",
		})
	}

	// Run ExecStart content checks.
	for _, line := range execLines {
		findings = append(findings, checkExecLine(line, path, "systemd")...)
	}

	return findings
}

// scanDropIn scans a single drop-in override file for ExecStart modifications.
func scanDropIn(path string) []scanner.Finding {
	var findings []scanner.Finding

	execLines := extractExecStartLines(path)
	if len(execLines) == 0 {
		return nil
	}

	// Any drop-in that modifies ExecStart is HIGH — common persistence technique.
	findings = append(findings, scanner.Finding{
		ID:          scanner.GenerateFindingID("systemd", path, "Drop-in override modifies ExecStart"),
		Scanner:     "systemd",
		Severity:    scanner.SevHigh,
		Title:       "Systemd drop-in override modifies ExecStart",
		Detail:      fmt.Sprintf("Drop-in file %s modifies ExecStart which is a common service-persistence technique.", path),
		Evidence:    strings.Join(execLines, "; "),
		Location:    path,
		Remediation: "Review the drop-in file and remove it if not intentional.",
	})

	// Also run content-level checks on each ExecStart line.
	for _, line := range execLines {
		findings = append(findings, checkExecLine(line, path, "systemd")...)
	}

	return findings
}

// scanSystemdTimer scans a .timer file and emits a finding.
func scanSystemdTimer(path string, isUserLevel bool) []scanner.Finding {
	if isUserLevel {
		name := filepath.Base(path)
		return []scanner.Finding{
			{
				ID:          scanner.GenerateFindingID("systemd", path, "User-level systemd timer"),
				Scanner:     "systemd",
				Severity:    scanner.SevMedium,
				Title:       "User-level systemd timer",
				Detail:      fmt.Sprintf("User-level timer %q found at %s — unusual on servers, review carefully.", name, path),
				Evidence:    path,
				Location:    path,
				Remediation: "If this timer is not intentional, remove the unit file and disable it with `systemctl --user disable " + name + "`.",
			},
		}
	}
	// System-level timers are not flagged on their own; they are noted only
	// if the service they trigger is already suspicious (future enhancement).
	return nil
}

// checkExecLine applies all suspicious-pattern and writable-path checks to a
// single ExecStart* value and returns any resulting findings.
func checkExecLine(line, location, scannerName string) []scanner.Finding {
	var findings []scanner.Finding

	// Pattern-based checks (curl|wget pipe, /dev/tcp, base64, etc.).
	for _, p := range suspiciousExecPatterns {
		if p.re.MatchString(line) {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID(scannerName, location, p.title),
				Scanner:     scannerName,
				Severity:    p.severity,
				Title:       p.title,
				Detail:      p.detail,
				Evidence:    line,
				Location:    location,
				Remediation: p.remediation,
			})
		}
	}

	// Extract the executable path from the ExecStart value (first token).
	execPath := extractExecPath(line)

	// Check for execution from writable staging directories (CRITICAL).
	for _, prefix := range writableStagingPrefixes {
		if strings.HasPrefix(execPath, prefix) {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID(scannerName, location, "Execution from world-writable directory"),
				Scanner:     scannerName,
				Severity:    scanner.SevCritical,
				Title:       "Systemd service executes from world-writable directory",
				Detail:      fmt.Sprintf("ExecStart points to %s which is world-writable and commonly used to stage malware.", execPath),
				Evidence:    line,
				Location:    location,
				Remediation: "Move the executable to a protected directory (e.g. /usr/local/bin) and update the service file.",
			})
			break
		}
	}

	return findings
}

// extractExecStartLines opens a unit file and returns all ExecStart*= values
// (the right-hand side of the key=value pair).
func extractExecStartLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		for _, field := range execStartFields {
			if strings.HasPrefix(raw, field) {
				value := strings.TrimPrefix(raw, field)
				if value != "" {
					lines = append(lines, value)
				}
				break
			}
		}
	}
	return lines
}

// extractExecPath returns the executable path from an ExecStart value.
// It strips leading flags like @, -, +, ! before the binary path.
func extractExecPath(execValue string) string {
	v := strings.TrimLeft(execValue, "@-+!")
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// isDpkgAvailable reports whether dpkg is present on the system.
func isDpkgAvailable() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}

// isOwnedByPackage returns true when dpkg -S reports that the given path
// belongs to an installed package.
func isOwnedByPackage(path string) bool {
	cmd := exec.Command("dpkg", "-S", path)
	err := cmd.Run()
	return err == nil
}
