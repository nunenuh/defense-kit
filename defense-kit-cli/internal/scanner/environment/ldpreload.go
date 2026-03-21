package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// LDPreloadScanner checks /etc/ld.so.preload and /etc/ld.so.conf.d/ for
// suspicious shared-library preload configurations.
type LDPreloadScanner struct{}

// NewLDPreloadScanner creates a new LDPreloadScanner.
func NewLDPreloadScanner() *LDPreloadScanner {
	return &LDPreloadScanner{}
}

func (s *LDPreloadScanner) Name() string           { return "ld_preload" }
func (s *LDPreloadScanner) Category() string       { return "environment" }
func (s *LDPreloadScanner) RequiresRoot() bool     { return true }
func (s *LDPreloadScanner) RequiredTools() []string { return nil }
func (s *LDPreloadScanner) OptionalTools() []string { return nil }
func (s *LDPreloadScanner) Available() bool        { return os.Geteuid() == 0 }
func (s *LDPreloadScanner) Description() string {
	return "Checks /etc/ld.so.preload for injected library entries and /etc/ld.so.conf.d/ for paths pointing to world-writable directories."
}

// Scan checks the LD preload configuration files for suspicious entries.
func (s *LDPreloadScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Check /etc/ld.so.preload — any entry here is suspicious.
	preloadFindings, err := scanLDSoPreload("/etc/ld.so.preload")
	if err == nil {
		findings = append(findings, preloadFindings...)
	}

	// Check /etc/ld.so.conf.d/ for entries pointing to /tmp, /dev/shm, /home.
	confDFindings, err := scanLDSoConfD("/etc/ld.so.conf.d")
	if err == nil {
		findings = append(findings, confDFindings...)
	}

	return findings, nil
}

// scanLDSoPreload reads /etc/ld.so.preload and flags any non-empty, non-comment line.
func scanLDSoPreload(path string) ([]scanner.Finding, error) {
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
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		location := fmt.Sprintf("%s:%d", path, lineNum)
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("ld_preload", location, "Library entry in ld.so.preload"),
			Scanner:     "ld_preload",
			Severity:    scanner.SevCritical,
			Title:       "Library entry in /etc/ld.so.preload",
			Detail:      fmt.Sprintf("The file /etc/ld.so.preload contains %q, which causes this library to be injected into every dynamic-linked process.", line),
			Evidence:    line,
			Location:    location,
			Remediation: "Remove entries from /etc/ld.so.preload unless explicitly required by a trusted application.",
		})
	}
	return findings, sc.Err()
}

// scanLDSoConfD reads .conf files in /etc/ld.so.conf.d/ and flags entries
// pointing to world-writable directories.
func scanLDSoConfD(dir string) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	suspectPrefixes := []string{"/tmp", "/dev/shm", "/home"}

	var findings []scanner.Finding
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		ff, err := scanLDConfFile(path, suspectPrefixes)
		if err != nil {
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// scanLDConfFile scans a single ld.so.conf.d file for suspicious directory entries.
func scanLDConfFile(path string, suspectPrefixes []string) ([]scanner.Finding, error) {
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
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, prefix := range suspectPrefixes {
			if strings.HasPrefix(line, prefix) {
				location := fmt.Sprintf("%s:%d", path, lineNum)
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("ld_preload", location, "Suspicious library path in ld.so.conf.d"),
					Scanner:     "ld_preload",
					Severity:    scanner.SevHigh,
					Title:       "Suspicious library path in ld.so.conf.d",
					Detail:      fmt.Sprintf("Library search path %q in %s points to a world-writable location, enabling library hijacking.", line, path),
					Evidence:    line,
					Location:    location,
					Remediation: "Remove suspicious directory entries from ld.so.conf.d and run ldconfig.",
				})
				break
			}
		}
	}
	return findings, sc.Err()
}
