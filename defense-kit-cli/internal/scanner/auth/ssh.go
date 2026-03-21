package auth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// homesGlobPattern is the glob used to find user home directories.
// It is overridable for testing.
const defaultHomesGlobPattern = "/home/*"

// SSHScanner checks SSH daemon configuration and authorized_keys files for
// weak or dangerous settings.
type SSHScanner struct {
	configPath       string
	homesGlobPattern string
}

// NewSSHScanner creates a new SSHScanner with production defaults.
func NewSSHScanner() *SSHScanner {
	return &SSHScanner{
		configPath:       sshdConfigPath,
		homesGlobPattern: defaultHomesGlobPattern,
	}
}

// NewSSHScannerWithConfig creates an SSHScanner that reads from a custom
// sshd_config path. Intended for testing.
func NewSSHScannerWithConfig(configPath string) *SSHScanner {
	return &SSHScanner{
		configPath:       configPath,
		homesGlobPattern: defaultHomesGlobPattern,
	}
}

// NewSSHScannerWithHomesDir creates an SSHScanner that reads a custom
// sshd_config path and scans a single custom home directory for
// authorized_keys. Intended for testing.
func NewSSHScannerWithHomesDir(configPath, homeDir string) *SSHScanner {
	return &SSHScanner{
		configPath:       configPath,
		homesGlobPattern: filepath.Join(homeDir),
	}
}

func (s *SSHScanner) Name() string            { return "ssh" }
func (s *SSHScanner) Category() string        { return "auth" }
func (s *SSHScanner) RequiresRoot() bool      { return true }
func (s *SSHScanner) RequiredTools() []string { return nil }
func (s *SSHScanner) OptionalTools() []string { return nil }
func (s *SSHScanner) Available() bool         { return true }
func (s *SSHScanner) Description() string {
	return "Checks /etc/ssh/sshd_config for weak settings (PermitRootLogin, PasswordAuthentication, MaxAuthTries, PermitEmptyPasswords) and authorized_keys files for world-readable permissions."
}

// Scan runs all SSH checks and returns the collected findings.
func (s *SSHScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	configFindings, err := s.checkSshdConfig(s.configPath)
	if err != nil {
		// Non-fatal: report as a single finding if the file is unreadable.
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), s.configPath, "sshd_config unreadable"),
			Scanner:  s.Name(),
			Severity: scanner.SevHigh,
			Title:    "sshd_config could not be read",
			Detail:   fmt.Sprintf("Failed to open %s: %v", s.configPath, err),
			Location: s.configPath,
		})
	} else {
		findings = append(findings, configFindings...)
	}

	keyFindings := s.checkAuthorizedKeys()
	findings = append(findings, keyFindings...)

	return findings, nil
}

// checkSshdConfig parses the given sshd_config file and returns findings for
// dangerous directive values.
func (s *SSHScanner) checkSshdConfig(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		directive := strings.ToLower(parts[0])
		value := strings.ToLower(parts[1])

		switch directive {
		case "permitrootlogin":
			if value == "yes" {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID(s.Name(), path, "PermitRootLogin yes"),
					Scanner:     s.Name(),
					Severity:    scanner.SevCritical,
					Title:       "PermitRootLogin is enabled",
					Detail:      "Allowing direct root login over SSH gives attackers unrestricted access if credentials are compromised.",
					Evidence:    line,
					Location:    path,
					Remediation: "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in sshd_config.",
					References: []string{
						"https://www.ssh.com/academy/ssh/sshd_config#permitrootlogin",
					},
				})
			}

		case "passwordauthentication":
			if value == "yes" {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID(s.Name(), path, "PasswordAuthentication yes"),
					Scanner:     s.Name(),
					Severity:    scanner.SevHigh,
					Title:       "PasswordAuthentication is enabled",
					Detail:      "Password-based SSH authentication is susceptible to brute-force attacks. Key-based authentication is preferred.",
					Evidence:    line,
					Location:    path,
					Remediation: "Set 'PasswordAuthentication no' and use SSH keys instead.",
					References: []string{
						"https://www.ssh.com/academy/ssh/sshd_config#passwordauthentication",
					},
				})
			}

		case "maxauthtries":
			n, convErr := strconv.Atoi(parts[1])
			if convErr == nil && n > 6 {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID(s.Name(), path, "MaxAuthTries > 6"),
					Scanner:     s.Name(),
					Severity:    scanner.SevMedium,
					Title:       "MaxAuthTries is set too high",
					Detail:      fmt.Sprintf("MaxAuthTries is %d. Values above 6 allow excessive password-guessing attempts per connection.", n),
					Evidence:    line,
					Location:    path,
					Remediation: "Set 'MaxAuthTries 3' or lower in sshd_config.",
				})
			}

		case "permitemptypasswords":
			if value == "yes" {
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID(s.Name(), path, "PermitEmptyPasswords yes"),
					Scanner:     s.Name(),
					Severity:    scanner.SevCritical,
					Title:       "PermitEmptyPasswords is enabled",
					Detail:      "Allowing SSH login with empty passwords provides trivial unauthorized access to any account without a password set.",
					Evidence:    line,
					Location:    path,
					Remediation: "Set 'PermitEmptyPasswords no' in sshd_config.",
					References: []string{
						"https://www.ssh.com/academy/ssh/sshd_config#permitemptypasswords",
					},
				})
			}
		}
	}

	if err := sc.Err(); err != nil {
		return findings, fmt.Errorf("reading %s: %w", path, err)
	}

	return findings, nil
}

// checkAuthorizedKeys inspects ~/.ssh/authorized_keys for every user whose
// home directory matches the scanner's homes glob pattern.
func (s *SSHScanner) checkAuthorizedKeys() []scanner.Finding {
	pattern := s.homesGlobPattern
	// If the pattern doesn't contain a glob wildcard it is a single directory
	// (used in tests), so list it directly.
	var homeDirs []string
	if !strings.ContainsAny(pattern, "*?[") {
		if _, err := os.Stat(pattern); err == nil {
			homeDirs = []string{pattern}
		}
	} else {
		var err error
		homeDirs, err = filepath.Glob(pattern)
		if err != nil || len(homeDirs) == 0 {
			return nil
		}
	}
	if len(homeDirs) == 0 {
		return nil
	}

	var findings []scanner.Finding

	for _, homeDir := range homeDirs {
		keyFile := filepath.Join(homeDir, ".ssh", "authorized_keys")

		info, err := os.Stat(keyFile)
		if err != nil {
			// File does not exist or is inaccessible — skip silently.
			continue
		}

		// Count key entries.
		count := countLines(keyFile)
		loc := keyFile

		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), loc, "authorized_keys present"),
			Scanner:  s.Name(),
			Severity: scanner.SevLow,
			Title:    "authorized_keys file present",
			Detail:   fmt.Sprintf("%s contains %d authorized key(s).", keyFile, count),
			Evidence: fmt.Sprintf("file: %s, keys: %d", keyFile, count),
			Location: loc,
			Metadata: map[string]string{
				"key_count": strconv.Itoa(count),
				"user_home": homeDir,
			},
		})

		// Flag world-readable authorized_keys.
		mode := info.Mode()
		if mode&0o004 != 0 {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID(s.Name(), loc, "authorized_keys world-readable"),
				Scanner:     s.Name(),
				Severity:    scanner.SevHigh,
				Title:       "authorized_keys is world-readable",
				Detail:      fmt.Sprintf("%s has permissions %s, allowing any user to read authorized public keys.", keyFile, mode.String()),
				Evidence:    fmt.Sprintf("permissions: %s", mode.String()),
				Location:    loc,
				Remediation: "Run: chmod 600 " + keyFile,
				CanAutoFix:  true,
			})
		}
	}

	return findings
}

// countLines returns the number of non-empty, non-comment lines in a file.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}
