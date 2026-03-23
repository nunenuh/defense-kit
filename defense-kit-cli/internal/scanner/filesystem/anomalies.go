package filesystem

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// AnomaliesScanner detects filesystem anomalies such as hidden files in
// unexpected locations, world-writable directories, and unusual file types.
type AnomaliesScanner struct {
	// tmpDirs are the temporary directories to scan for suspicious files.
	tmpDirs []string
	// systemBinDirs are directories where hidden files are suspicious.
	systemBinDirs []string
	// worldWritableDirs are directories to check for world-writable subdirectories.
	worldWritableDirs []string
}

// NewAnomaliesScanner creates a new AnomaliesScanner.
func NewAnomaliesScanner() *AnomaliesScanner {
	return &AnomaliesScanner{
		tmpDirs:           []string{"/tmp", "/var/tmp", "/dev/shm"},
		systemBinDirs:     []string{"/usr", "/bin", "/sbin"},
		worldWritableDirs: []string{"/tmp", "/var/tmp", "/dev/shm"},
	}
}

// NewAnomaliesScannerWithDirs creates an AnomaliesScanner with custom
// directories (used in tests).
func NewAnomaliesScannerWithDirs(tmpDirs, systemBinDirs, worldWritableDirs []string) *AnomaliesScanner {
	return &AnomaliesScanner{
		tmpDirs:           tmpDirs,
		systemBinDirs:     systemBinDirs,
		worldWritableDirs: worldWritableDirs,
	}
}

func (s *AnomaliesScanner) Name() string           { return "filesystem" }
func (s *AnomaliesScanner) Category() string       { return "filesystem" }
func (s *AnomaliesScanner) RequiresRoot() bool     { return false }
func (s *AnomaliesScanner) RequiredTools() []string { return nil }
func (s *AnomaliesScanner) OptionalTools() []string { return nil }
func (s *AnomaliesScanner) Available() bool        { return true }
func (s *AnomaliesScanner) Description() string {
	return "Detects filesystem anomalies such as hidden files in unexpected locations, world-writable directories, and unusual file types."
}

// Scan detects filesystem anomalies.
func (s *AnomaliesScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check tmp dirs for suspicious files.
	for _, dir := range s.tmpDirs {
		ff := s.scanTmpDir(dir)
		findings = append(findings, ff...)
	}

	// Check system binary dirs for hidden files.
	for _, dir := range s.systemBinDirs {
		ff := s.findHiddenFiles(dir)
		findings = append(findings, ff...)
	}

	// Check common dirs for world-writable directories.
	for _, dir := range s.worldWritableDirs {
		ff := s.findWorldWritableDirs(dir)
		findings = append(findings, ff...)
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// scanTmpDir scans a temporary directory for suspicious files: executables
// older than 7 days, root-owned but world-writable files, and hidden dotfiles.
func (s *AnomaliesScanner) scanTmpDir(dir string) []scanner.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var findings []scanner.Finding
	now := time.Now()
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()

		// Hidden dotfiles in tmp dirs are suspicious.
		if len(name) > 1 && name[0] == '.' {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("filesystem", path, "Hidden dotfile in temp directory"),
				Scanner:     "filesystem",
				Severity:    scanner.SevMedium,
				Title:       "Hidden dotfile in temporary directory",
				Detail:      fmt.Sprintf("Hidden file %q found in %s. Attackers often hide malware or configuration files as dotfiles in world-writable directories.", path, dir),
				Evidence:    fmt.Sprintf("path: %s, mode: %s", path, mode.String()),
				Location:    path,
				Remediation: fmt.Sprintf("Investigate the purpose of %s and remove if not legitimate.", path),
			})
		}

		// Executables in /tmp older than 7 days are suspicious.
		if mode&0o111 != 0 && !mode.IsDir() && info.ModTime().Before(sevenDaysAgo) {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("filesystem", path, "Old executable in temp directory"),
				Scanner:     "filesystem",
				Severity:    scanner.SevMedium,
				Title:       "Executable in temporary directory older than 7 days",
				Detail:      fmt.Sprintf("Executable file %q in %s has not been modified for more than 7 days. Legitimate temporary executables are typically short-lived.", path, dir),
				Evidence:    fmt.Sprintf("path: %s, mtime: %s, mode: %s", path, info.ModTime().Format(time.RFC3339), mode.String()),
				Location:    path,
				Remediation: fmt.Sprintf("Investigate the purpose of %s. If it is not a known legitimate file, remove it.", path),
			})
		}

		// World-writable files owned by root in tmp dirs are a risk.
		if mode&0o002 != 0 {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("filesystem", path, "World-writable file in temp directory"),
				Scanner:     "filesystem",
				Severity:    scanner.SevMedium,
				Title:       "World-writable file in temporary directory",
				Detail:      fmt.Sprintf("File %q in %s is world-writable. Any user can modify this file.", path, dir),
				Evidence:    fmt.Sprintf("path: %s, mode: %s", path, mode.String()),
				Location:    path,
				Remediation: fmt.Sprintf("Run: chmod o-w %s", path),
				CanAutoFix:  true,
			})
		}
	}
	return findings
}

// findHiddenFiles looks for hidden files (dotfiles) in system binary directories.
func (s *AnomaliesScanner) findHiddenFiles(dir string) []scanner.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		// Recurse into subdirectories but skip known hidden dirs.
		if entry.IsDir() {
			name := entry.Name()
			// Skip hidden directories at this level too.
			if len(name) > 1 && name[0] == '.' {
				path := filepath.Join(dir, name)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("filesystem", path, "Hidden directory in system path"),
					Scanner:     "filesystem",
					Severity:    scanner.SevHigh,
					Title:       "Hidden directory in system binary path",
					Detail:      fmt.Sprintf("Hidden directory %q found in %s. Rootkits and malware commonly use hidden directories in system paths to conceal files.", path, dir),
					Evidence:    fmt.Sprintf("path: %s", path),
					Location:    path,
					Remediation: fmt.Sprintf("Investigate the contents of %s. If it is not a known legitimate directory, remove it.", path),
				})
			}
			continue
		}
		name := entry.Name()
		if len(name) > 1 && name[0] == '.' {
			path := filepath.Join(dir, name)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("filesystem", path, "Hidden file in system binary path"),
				Scanner:     "filesystem",
				Severity:    scanner.SevHigh,
				Title:       "Hidden file in system binary path",
				Detail:      fmt.Sprintf("Hidden file %q found in %s. Rootkits and malware commonly hide files in system directories.", path, dir),
				Evidence:    fmt.Sprintf("path: %s", path),
				Location:    path,
				Remediation: fmt.Sprintf("Investigate the purpose of %s and remove if not legitimate.", path),
			})
		}
	}
	return findings
}

// findWorldWritableDirs scans a directory for world-writable subdirectories.
func (s *AnomaliesScanner) findWorldWritableDirs(dir string) []scanner.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()
		if mode&0o002 != 0 {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("filesystem", path, "World-writable directory"),
				Scanner:     "filesystem",
				Severity:    scanner.SevMedium,
				Title:       "World-writable directory found",
				Detail:      fmt.Sprintf("Directory %q is world-writable (mode %s). World-writable directories can be used by any user to plant files.", path, mode.String()),
				Evidence:    fmt.Sprintf("path: %s, mode: %s", path, mode.String()),
				Location:    path,
				Remediation: fmt.Sprintf("Run: chmod o-w %s", path),
				CanAutoFix:  true,
			})
		}
	}
	return findings
}
