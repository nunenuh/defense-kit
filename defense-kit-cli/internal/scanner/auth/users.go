package auth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const (
	passwdPath  = "/etc/passwd"
	shadowPath  = "/etc/shadow"
	sudoersPath = "/etc/sudoers"
	sudoersDDir = "/etc/sudoers.d"
	groupPath   = "/etc/group"
)

// privilegedGroups are groups whose membership grants elevated privileges.
var privilegedGroups = []string{"sudo", "admin", "wheel"}

// UsersScanner audits local user accounts for dangerous configuration.
type UsersScanner struct {
	passwdPath  string
	shadowPath  string
	sudoersPath string
	sudoersDDir string
	groupPath   string
}

// NewUsersScanner creates a new UsersScanner with production defaults.
func NewUsersScanner() *UsersScanner {
	return &UsersScanner{
		passwdPath:  passwdPath,
		shadowPath:  shadowPath,
		sudoersPath: sudoersPath,
		sudoersDDir: sudoersDDir,
		groupPath:   groupPath,
	}
}

// NewUsersScannerWithPaths creates a UsersScanner that reads from custom paths.
// Intended for testing.
func NewUsersScannerWithPaths(passwd, shadow, sudoers, sudoersD, group string) *UsersScanner {
	return &UsersScanner{
		passwdPath:  passwd,
		shadowPath:  shadow,
		sudoersPath: sudoers,
		sudoersDDir: sudoersD,
		groupPath:   group,
	}
}

func (s *UsersScanner) Name() string            { return "users" }
func (s *UsersScanner) Category() string        { return "auth" }
func (s *UsersScanner) RequiresRoot() bool      { return true }
func (s *UsersScanner) RequiredTools() []string { return nil }
func (s *UsersScanner) OptionalTools() []string { return nil }
func (s *UsersScanner) Available() bool         { return true }
func (s *UsersScanner) Description() string {
	return "Audits local user accounts for dangerous configuration such as UID 0 accounts, passwordless users, and stale accounts."
}

// passwdEntry holds a parsed line from /etc/passwd.
type passwdEntry struct {
	username string
	uid      string
	shell    string
}

// shadowEntry holds relevant fields from /etc/shadow.
type shadowEntry struct {
	username     string
	passwordHash string
}

// Scan runs all user account checks and returns the collected findings.
func (s *UsersScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	passwdEntries, err := parsePasswd(s.passwdPath)
	if err != nil {
		// Non-fatal: report it and continue with what we have.
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), s.passwdPath, "passwd unreadable"),
			Scanner:  s.Name(),
			Severity: scanner.SevHigh,
			Title:    "/etc/passwd could not be read",
			Detail:   fmt.Sprintf("Failed to open %s: %v", s.passwdPath, err),
			Location: s.passwdPath,
		})
		return findings, nil
	}

	// Build a username→entry map for cross-reference with shadow.
	passwdByUser := make(map[string]passwdEntry, len(passwdEntries))
	for _, e := range passwdEntries {
		passwdByUser[e.username] = e
	}

	// Check 1 & 5: UID 0 accounts that are not "root".
	for _, e := range passwdEntries {
		if e.uid == "0" && e.username != "root" {
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID(s.Name(), s.passwdPath, "uid0-"+e.username),
				Scanner:  s.Name(),
				Severity: scanner.SevCritical,
				Title:    fmt.Sprintf("Non-root account with UID 0: %s", e.username),
				Detail:   fmt.Sprintf("Account %q has UID 0, which grants full root privileges. Only the 'root' account should have UID 0.", e.username),
				Evidence: fmt.Sprintf("username=%s uid=%s", e.username, e.uid),
				Location: s.passwdPath,
				Remediation: fmt.Sprintf(
					"Investigate account %q. If not required, remove it or change its UID. Run: userdel %s", e.username, e.username),
				References: []string{
					"https://www.cisecurity.org/benchmark/",
				},
			})
		}
	}

	// Check 2: Passwordless accounts with an active shell.
	shadowEntries, shadowErr := parseShadow(s.shadowPath)
	if shadowErr == nil {
		activeShells := map[string]bool{
			"/usr/sbin/nologin": false,
			"/bin/false":        false,
			"/sbin/nologin":     false,
			"/dev/null":         false,
		}

		for _, se := range shadowEntries {
			// An empty password field means no password — "!" or "*" means locked.
			if se.passwordHash != "" {
				continue
			}
			pe, found := passwdByUser[se.username]
			if !found {
				continue
			}
			// Check if the shell is an active interactive shell.
			shell := strings.TrimSpace(pe.shell)
			if active, restricted := activeShells[shell]; !active || !restricted {
				// Not in the restricted map at all → active shell.
				if _, isRestricted := activeShells[shell]; !isRestricted {
					findings = append(findings, scanner.Finding{
						ID:       scanner.GenerateFindingID(s.Name(), s.shadowPath, "passwordless-"+se.username),
						Scanner:  s.Name(),
						Severity: scanner.SevHigh,
						Title:    fmt.Sprintf("Account %s has no password and an active shell", se.username),
						Detail:   fmt.Sprintf("Account %q has an empty password field in /etc/shadow and uses shell %q, meaning anyone can log in as this user.", se.username, shell),
						Evidence: fmt.Sprintf("username=%s shell=%s password_field=empty", se.username, shell),
						Location: s.shadowPath,
						Remediation: fmt.Sprintf(
							"Lock the account or set a password: passwd -l %s", se.username),
					})
				}
			}
		}
	}
	// If shadow is unreadable we silently skip — scanner may not run as root.

	// Check 3: NOPASSWD in sudoers.
	sudoersFindings := s.checkSudoers()
	findings = append(findings, sudoersFindings...)

	// Check 4: Users in privileged groups.
	groupFindings := s.checkPrivilegedGroups()
	findings = append(findings, groupFindings...)

	return findings, nil
}

// parsePasswd parses /etc/passwd and returns a slice of entries.
// Format: username:x:uid:gid:comment:home:shell
func parsePasswd(path string) ([]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []passwdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		entries = append(entries, passwdEntry{
			username: fields[0],
			uid:      fields[2],
			shell:    fields[6],
		})
	}
	return entries, sc.Err()
}

// parseShadow parses /etc/shadow and returns a slice of entries.
// Format: username:password_hash:last_changed:...
func parseShadow(path string) ([]shadowEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []shadowEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		entries = append(entries, shadowEntry{
			username:     fields[0],
			passwordHash: fields[1],
		})
	}
	return entries, sc.Err()
}

// checkSudoers scans /etc/sudoers and all files in /etc/sudoers.d/ for
// NOPASSWD directives.
func (s *UsersScanner) checkSudoers() []scanner.Finding {
	var findings []scanner.Finding

	// Collect all sudoers files to examine.
	files := []string{s.sudoersPath}

	if s.sudoersDDir != "" {
		entries, err := os.ReadDir(s.sudoersDDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(s.sudoersDDir, e.Name()))
				}
			}
		}
	}

	for _, path := range files {
		ff := parseSudoersFile(s.Name(), path)
		findings = append(findings, ff...)
	}

	return findings
}

// parseSudoersFile reads a single sudoers file and flags NOPASSWD lines.
func parseSudoersFile(scannerName, path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		upperLine := strings.ToUpper(line)
		if !strings.Contains(upperLine, "NOPASSWD") {
			continue
		}

		// Extract the username/alias from the sudoers rule.
		// Typical format: username  ALL=(ALL) NOPASSWD: ALL
		username := extractSudoersSubject(line)

		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID(scannerName, path, "nopasswd-"+username),
			Scanner:     scannerName,
			Severity:    scanner.SevHigh,
			Title:       fmt.Sprintf("NOPASSWD sudo for %s", username),
			Detail:      fmt.Sprintf("The sudoers rule for %q grants sudo access without requiring a password. This can allow privilege escalation without authentication.", username),
			Evidence:    line,
			Location:    path,
			Remediation: fmt.Sprintf("Remove NOPASSWD from the sudoers rule for %q. Require password confirmation for sudo.", username),
			References: []string{
				"https://www.sudo.ws/docs/man/1.8.27/sudoers.man/",
			},
		})
	}

	return findings
}

// extractSudoersSubject returns the subject (user, group, or alias) from a
// sudoers rule line.  Falls back to the full line on parse failure.
func extractSudoersSubject(line string) string {
	// Sudoers format: subject  host=(runas) options: commands
	// The subject is the first whitespace-delimited token.
	fields := strings.Fields(line)
	if len(fields) > 0 {
		return fields[0]
	}
	return line
}

// checkPrivilegedGroups reads /etc/group and reports members of privileged
// groups (sudo, admin, wheel) as LOW-severity informational findings.
func (s *UsersScanner) checkPrivilegedGroups() []scanner.Finding {
	f, err := os.Open(s.groupPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: groupname:x:gid:user1,user2,...
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		if !isPrivilegedGroup(groupName) {
			continue
		}
		members := strings.TrimSpace(fields[3])
		if members == "" {
			continue
		}

		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("users", s.groupPath, "privgroup-"+groupName),
			Scanner:  "users",
			Severity: scanner.SevLow,
			Title:    fmt.Sprintf("Users in privileged group %q: %s", groupName, members),
			Detail:   fmt.Sprintf("The following users are members of the privileged group %q: %s. Review to ensure membership is intended.", groupName, members),
			Evidence: line,
			Location: s.groupPath,
		})
	}

	return findings
}

// isPrivilegedGroup reports whether the group name is a known privileged group.
func isPrivilegedGroup(name string) bool {
	for _, g := range privilegedGroups {
		if name == g {
			return true
		}
	}
	return false
}
