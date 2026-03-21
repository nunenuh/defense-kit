package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// knownSafeSUID is the set of binaries that commonly have SUID bits set on a
// standard Linux system and are considered safe.
var knownSafeSUID = map[string]bool{
	"sudo":    true,
	"passwd":  true,
	"ping":    true,
	"su":      true,
	"mount":   true,
	"umount":  true,
	"chsh":    true,
	"chfn":    true,
	"newgrp":  true,
	"gpasswd": true,
}

// scanDirs is the list of directories searched for SUID/SGID binaries.
var scanDirs = []string{
	"/usr/bin",
	"/usr/sbin",
	"/bin",
	"/sbin",
}

// IntegrityScanner checks for unexpected SUID/SGID binaries in common system
// directories.
type IntegrityScanner struct{}

// NewIntegrityScanner creates a new IntegrityScanner.
func NewIntegrityScanner() *IntegrityScanner {
	return &IntegrityScanner{}
}

func (s *IntegrityScanner) Name() string           { return "file_integrity" }
func (s *IntegrityScanner) Category() string       { return "filesystem" }
func (s *IntegrityScanner) RequiresRoot() bool     { return true }
func (s *IntegrityScanner) RequiredTools() []string { return nil }
func (s *IntegrityScanner) OptionalTools() []string { return nil }
func (s *IntegrityScanner) Available() bool        { return true }
func (s *IntegrityScanner) Description() string {
	return "Scans common system directories for unexpected SUID/SGID binaries that are not in the known-safe list."
}

// Scan walks the standard system binary directories and flags any SUID/SGID
// binary that is not present in the known-safe list.
func (s *IntegrityScanner) Scan(_ context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	dirs := scanDirs
	if len(opts.TargetPaths) > 0 {
		dirs = opts.TargetPaths
	}

	var findings []scanner.Finding

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Directory may not exist on all systems; skip gracefully.
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			fullPath := filepath.Join(dir, entry.Name())
			info, err := os.Lstat(fullPath)
			if err != nil {
				continue
			}

			mode := info.Mode()
			hasSUID := mode&fs.ModeSetuid != 0
			hasSGID := mode&fs.ModeSetgid != 0

			if !hasSUID && !hasSGID {
				continue
			}

			// Only flag binaries not in the known-safe list.
			if knownSafeSUID[entry.Name()] {
				continue
			}

			bits := describeBits(mode)
			finding := scanner.Finding{
				ID:          scanner.GenerateFindingID("file_integrity", fullPath, "Unexpected SUID/SGID binary"),
				Scanner:     "file_integrity",
				Severity:    scanner.SevHigh,
				Title:       "Unexpected SUID/SGID binary",
				Detail:      fmt.Sprintf("Binary %q has SUID/SGID bits set and is not in the known-safe list. This may indicate a privilege escalation vector.", fullPath),
				Evidence:    fmt.Sprintf("path=%s permissions=%s", fullPath, bits),
				Location:    fullPath,
				Remediation: fmt.Sprintf("Verify whether %q requires elevated permissions. If not, remove the SUID/SGID bits: chmod u-s,g-s %s", entry.Name(), fullPath),
				References: []string{
					"https://www.linux.com/training-tutorials/what-suid-and-how-set-suid-linuxunix/",
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// describeBits returns a human-readable permission string for a file mode,
// including the SUID/SGID indicators.
func describeBits(mode fs.FileMode) string {
	perm := mode.Perm()
	var flags string
	if mode&fs.ModeSetuid != 0 {
		flags += "SUID "
	}
	if mode&fs.ModeSetgid != 0 {
		flags += "SGID "
	}
	return fmt.Sprintf("%04o (%s)", perm, flags)
}
