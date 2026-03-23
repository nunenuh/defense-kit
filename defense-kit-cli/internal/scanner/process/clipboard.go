package process

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// clipboardPattern describes a suspicious process pattern related to
// clipboard/keyboard monitoring.
type clipboardPattern struct {
	re          *regexp.Regexp
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

// clipboardPatterns lists patterns indicating clipboard or keylogger activity.
var clipboardPatterns = []clipboardPattern{
	{
		re:          regexp.MustCompile(`(?i)\bxinput\b.*\btest\b`),
		title:       "X11 keyboard event logger (xinput test)",
		severity:    scanner.SevCritical,
		detail:      "A process is running 'xinput test', which captures all X11 keyboard events. This is a classic keylogger technique used to steal passwords and sensitive input.",
		remediation: "Kill the process immediately and investigate how it was started. Check for cron jobs, systemd units, or shell profiles that could restart it.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bxspy\b`),
		title:       "X11 spy tool (xspy) running",
		severity:    scanner.SevCritical,
		detail:      "xspy is an X11 keyboard sniffing utility. Its presence as a running process strongly indicates malicious keylogging activity.",
		remediation: "Kill the process and remove the binary. Investigate the source of the compromise.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bxev\b`),
		title:       "X11 event monitor (xev) running",
		severity:    scanner.SevHigh,
		detail:      "xev captures all X11 events including keystrokes. While it is a legitimate debugging tool, it should not be running in production environments.",
		remediation: "Verify whether xev was intentionally started. If not, kill the process and investigate.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bxdotool\b`),
		title:       "X11 automation tool (xdotool) running",
		severity:    scanner.SevHigh,
		detail:      "xdotool can simulate keyboard/mouse input and read window content. It is sometimes used for UI automation but can also be misused for credential capture.",
		remediation: "Verify whether xdotool was intentionally started. If unexpected, kill the process and investigate.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bxclip\b.*-[oO]`),
		title:       "Clipboard content being read (xclip -out)",
		severity:    scanner.SevHigh,
		detail:      "A process is reading clipboard contents via xclip -out/-o. Repeated clipboard reads in a loop are a common technique to steal copied credentials or cryptocurrency addresses.",
		remediation: "Verify whether this clipboard access is legitimate. If unexpected, kill the process and investigate for persistence mechanisms.",
	},
	{
		re:          regexp.MustCompile(`(?i)\bxdotool\b.*getclipboard`),
		title:       "Clipboard content being read (xdotool getclipboard)",
		severity:    scanner.SevHigh,
		detail:      "A process is reading clipboard contents via xdotool getclipboard. This can be used to steal passwords or cryptocurrency addresses copied by the user.",
		remediation: "Verify whether this clipboard access is legitimate. If unexpected, kill the process and investigate for persistence mechanisms.",
	},
}

// x11SniffingPatterns matches process names that are associated with X11
// sniffing when they have DISPLAY set.
var x11SniffingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(keystroke|keylogger|keysniffer|logkeys|lkl)\b`),
}

// ClipboardScanner checks for processes accessing the clipboard in unexpected ways.
type ClipboardScanner struct {
	// procRoot is the root of the proc filesystem; overrideable in tests.
	procRoot string
}

// NewClipboardScanner creates a new ClipboardScanner.
func NewClipboardScanner() *ClipboardScanner {
	return &ClipboardScanner{procRoot: "/proc"}
}

// NewClipboardScannerWithRoot creates a ClipboardScanner with a custom proc
// root (used in tests).
func NewClipboardScannerWithRoot(procRoot string) *ClipboardScanner {
	return &ClipboardScanner{procRoot: procRoot}
}

func (s *ClipboardScanner) Name() string           { return "clipboard" }
func (s *ClipboardScanner) Category() string       { return "process" }
func (s *ClipboardScanner) RequiresRoot() bool     { return false }
func (s *ClipboardScanner) RequiredTools() []string { return nil }
func (s *ClipboardScanner) OptionalTools() []string { return nil }
func (s *ClipboardScanner) Available() bool        { return true }
func (s *ClipboardScanner) Description() string {
	return "Detects processes that are accessing or hijacking the system clipboard, which can be used to steal credentials or replace cryptocurrency addresses."
}

// Scan checks for processes with suspicious clipboard access.
func (s *ClipboardScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		// /proc not available (e.g., non-Linux) — skip gracefully.
		return nil, nil
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

		cmdline, err := readCmdline(filepath.Join(s.procRoot, pid, "cmdline"))
		if err != nil || cmdline == "" {
			continue
		}

		ff := s.checkClipboardProcess(pid, cmdline)
		findings = append(findings, ff...)
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkClipboardProcess checks a single process for clipboard/keylogger indicators.
func (s *ClipboardScanner) checkClipboardProcess(pid, cmdline string) []scanner.Finding {
	var findings []scanner.Finding

	// Check against known clipboard/keylogger patterns.
	for _, p := range clipboardPatterns {
		if p.re.MatchString(cmdline) {
			location := fmt.Sprintf("/proc/%s/cmdline", pid)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("clipboard", location, p.title),
				Scanner:     "clipboard",
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

	// Check for X11 sniffing: processes with suspicious names.
	for _, re := range x11SniffingPatterns {
		if re.MatchString(cmdline) {
			// Also check if DISPLAY is set in the process environment.
			envPath := filepath.Join(s.procRoot, pid, "environ")
			display := readEnvVar(envPath, "DISPLAY")
			if display != "" {
				location := fmt.Sprintf("/proc/%s/cmdline", pid)
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID("clipboard", location, "X11 sniffing process"),
					Scanner:  "clipboard",
					Severity: scanner.SevHigh,
					Title:    "Suspected X11 keylogger/sniffer process",
					Detail: fmt.Sprintf(
						"Process PID %s (%q) has DISPLAY=%s set and matches a known keylogger/sniffer pattern. This process may be capturing X11 keyboard or clipboard events.",
						pid, cmdline, display,
					),
					Evidence:    cmdline,
					Location:    location,
					Remediation: "Kill the process and investigate its origin. Check for persistence mechanisms (cron, systemd, shell profiles).",
					Metadata:    map[string]string{"pid": pid, "DISPLAY": display},
				})
			}
		}
	}

	return findings
}

// readEnvVar reads a specific environment variable from /proc/<pid>/environ.
// Returns "" if the variable is not set or the file is not readable.
func readEnvVar(environPath, varName string) string {
	data, err := os.ReadFile(environPath)
	if err != nil {
		return ""
	}
	prefix := varName + "="
	for _, entry := range bytes.Split(data, []byte{0}) {
		if strings.HasPrefix(string(entry), prefix) {
			return strings.TrimPrefix(string(entry), prefix)
		}
	}
	return ""
}
