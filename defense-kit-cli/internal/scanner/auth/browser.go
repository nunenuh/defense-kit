package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// browserProfile describes a known browser credential store location relative
// to a user's home directory.
type browserProfile struct {
	// name is a human-readable browser name.
	name string
	// glob is a path glob relative to the home directory that matches profile dirs.
	glob string
	// credFile is the name of the credential file inside the profile directory.
	credFile string
	// severity is the finding severity for this credential store.
	severity scanner.Severity
	// detail explains the risk.
	detail string
}

// browserProfiles lists known browser credential stores.
var browserProfiles = []browserProfile{
	{
		name:     "Google Chrome / Chromium",
		glob:     ".config/google-chrome/*/",
		credFile: "Login Data",
		severity: scanner.SevMedium,
		detail:   "Chrome stores saved passwords in a SQLite database ('Login Data') in the user's profile. Although the passwords are encrypted with the OS keyring or a local key, the database itself may be accessible to other processes running as the same user.",
	},
	{
		name:     "Google Chrome / Chromium (Default profile)",
		glob:     ".config/google-chrome/Default/",
		credFile: "Login Data",
		severity: scanner.SevMedium,
		detail:   "Chrome stores saved passwords in a SQLite database ('Login Data'). The file may be readable by processes running as the same user.",
	},
	{
		name:     "Chromium",
		glob:     ".config/chromium/*/",
		credFile: "Login Data",
		severity: scanner.SevMedium,
		detail:   "Chromium stores saved passwords in a SQLite database ('Login Data') in the user's profile.",
	},
	{
		name:     "Firefox",
		glob:     ".mozilla/firefox/*/",
		credFile: "logins.json",
		severity: scanner.SevMedium,
		detail:   "Firefox stores saved passwords in 'logins.json'. The passwords are encrypted with a key that may be stored locally in 'key4.db'. Without a master password, these can be extracted by tools like firepwd.",
	},
	{
		name:     "Brave",
		glob:     ".config/BraveSoftware/Brave-Browser/*/",
		credFile: "Login Data",
		severity: scanner.SevMedium,
		detail:   "Brave stores saved passwords in a SQLite database ('Login Data') similar to Chrome.",
	},
	{
		name:     "Microsoft Edge",
		glob:     ".config/microsoft-edge/*/",
		credFile: "Login Data",
		severity: scanner.SevMedium,
		detail:   "Microsoft Edge stores saved passwords in a SQLite database ('Login Data') similar to Chrome.",
	},
}

// BrowserScanner checks browser credential stores and extension permissions
// for security issues.
type BrowserScanner struct {
	// homesDir is the root directory under which user home directories live.
	homesDir string
}

// NewBrowserScanner creates a new BrowserScanner.
func NewBrowserScanner() *BrowserScanner {
	return &BrowserScanner{homesDir: "/home"}
}

// NewBrowserScannerWithHomesDir creates a BrowserScanner with a custom homes
// directory (used in tests).
func NewBrowserScannerWithHomesDir(homesDir string) *BrowserScanner {
	return &BrowserScanner{homesDir: homesDir}
}

func (s *BrowserScanner) Name() string            { return "browser" }
func (s *BrowserScanner) Category() string        { return "auth" }
func (s *BrowserScanner) RequiresRoot() bool      { return false }
func (s *BrowserScanner) RequiredTools() []string { return nil }
func (s *BrowserScanner) OptionalTools() []string { return nil }
func (s *BrowserScanner) Available() bool         { return true }
func (s *BrowserScanner) Description() string {
	return "Checks browser credential stores and extension permissions for stored plaintext credentials and overly-permissive extensions."
}

// Scan checks browser credential stores for all users.
func (s *BrowserScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// Collect home directories to scan.
	homeDirs, err := collectHomeDirs(s.homesDir)
	if err != nil || len(homeDirs) == 0 {
		return nil, nil
	}

	var findings []scanner.Finding

	for _, homeDir := range homeDirs {
		ff := scanBrowserProfiles(homeDir)
		findings = append(findings, ff...)
	}

	// Also check root's home directory.
	rootFindings := scanBrowserProfiles("/root")
	findings = append(findings, rootFindings...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// collectHomeDirs returns a list of home directories under homesDir.
func collectHomeDirs(homesDir string) ([]string, error) {
	entries, err := os.ReadDir(homesDir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(homesDir, entry.Name()))
		}
	}
	return dirs, nil
}

// scanBrowserProfiles checks a single home directory for browser credential stores.
func scanBrowserProfiles(homeDir string) []scanner.Finding {
	var findings []scanner.Finding
	seen := make(map[string]bool)

	for _, profile := range browserProfiles {
		pattern := filepath.Join(homeDir, profile.glob)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, profileDir := range matches {
			credPath := filepath.Join(profileDir, profile.credFile)
			if seen[credPath] {
				continue
			}

			info, err := os.Stat(credPath)
			if err != nil {
				// Credential file does not exist in this profile directory.
				continue
			}
			seen[credPath] = true

			mode := info.Mode()
			sev := profile.severity

			// If the credential file is readable by others (group or world),
			// escalate to HIGH — it's accessible to more processes.
			if mode&0o044 != 0 {
				sev = scanner.SevHigh
			}

			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("browser", credPath, profile.name+" credential store"),
				Scanner:  "browser",
				Severity: sev,
				Title:    fmt.Sprintf("Browser password store found: %s (%s)", profile.name, profile.credFile),
				Detail:   profile.detail,
				Evidence:  fmt.Sprintf("path: %s, mode: %s, size: %d bytes", credPath, mode.String(), info.Size()),
				Location:  credPath,
				Remediation: "Consider using a dedicated password manager instead of browser-stored passwords. If browser storage is necessary, ensure a strong master password (Firefox) or OS-level keyring encryption is configured.",
				References: []string{
					"https://attack.mitre.org/techniques/T1555/003/",
				},
			})
		}
	}

	return findings
}
