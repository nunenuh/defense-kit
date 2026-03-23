package filesystem_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/filesystem"
)

// ---------------------------------------------------------------------------
// IntegrityScanner
// ---------------------------------------------------------------------------

func TestIntegrityScanner_Interface(t *testing.T) {
	s := filesystem.NewIntegrityScanner()

	if s.Name() != "file_integrity" {
		t.Errorf("Name() = %q, want %q", s.Name(), "file_integrity")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should return nil")
	}
	if s.OptionalTools() != nil {
		t.Error("OptionalTools() should return nil")
	}
}

// TestIntegrityScanner_DetectsSUIDBinary creates a temp directory containing a
// fake binary with the SUID bit set (0o4755) and verifies that IntegrityScanner
// reports it as a HIGH finding.
func TestIntegrityScanner_DetectsSUIDBinary(t *testing.T) {
	dir := t.TempDir()

	// Create a fake binary with SUID bit set.
	fakeBin := filepath.Join(dir, "evilbin")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}
	if err := os.Chmod(fakeBin, 0o4755); err != nil {
		t.Fatalf("failed to set SUID bit: %v", err)
	}

	// Verify the SUID bit was actually set; some filesystems (e.g. overlayfs
	// in Docker without --privileged) silently drop the setuid bit.
	info, err := os.Lstat(fakeBin)
	if err != nil {
		t.Fatalf("os.Lstat failed: %v", err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("setuid bit could not be set in this environment (likely a restricted filesystem); skipping test")
	}

	s := filesystem.NewIntegrityScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}

	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for SUID binary, got none")
	}

	f := findings[0]
	if f.ID == "" {
		t.Error("finding has empty ID")
	}
	if f.Scanner != "file_integrity" {
		t.Errorf("finding Scanner = %q, want %q", f.Scanner, "file_integrity")
	}
	if f.Severity != scanner.SevHigh {
		t.Errorf("finding Severity = %v, want HIGH", f.Severity)
	}
	if f.Location == "" {
		t.Error("finding has empty Location")
	}
	if f.Evidence == "" {
		t.Error("finding has empty Evidence")
	}
}

// TestIntegrityScanner_SkipsKnownSafeBinaries verifies that binaries in the
// known-safe list (e.g., "sudo") do NOT produce findings even when they have
// the SUID bit set.
func TestIntegrityScanner_SkipsKnownSafeBinaries(t *testing.T) {
	dir := t.TempDir()

	// Create a fake "sudo" binary with SUID bit.
	fakeSudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(fakeSudo, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create fake sudo: %v", err)
	}
	if err := os.Chmod(fakeSudo, 0o4755); err != nil {
		t.Fatalf("failed to set SUID bit: %v", err)
	}
	// This test is valid whether or not the SUID bit was actually preserved:
	// if the bit can't be set, there won't be a finding (correct); if it can
	// be set, the known-safe list should suppress it (also correct).

	s := filesystem.NewIntegrityScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}

	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for known-safe binary, got %d: %+v", len(findings), findings)
	}
}

// TestIntegrityScanner_NoFindingsForNormalBinary verifies that a binary with
// standard permissions (0o755) does not produce any findings.
func TestIntegrityScanner_NoFindingsForNormalBinary(t *testing.T) {
	dir := t.TempDir()

	normalBin := filepath.Join(dir, "normalbin")
	if err := os.WriteFile(normalBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create normal binary: %v", err)
	}

	s := filesystem.NewIntegrityScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}

	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestIntegrityScanner_DetectsSGIDBinary verifies that a binary with only the
// SGID bit set is also flagged.
func TestIntegrityScanner_DetectsSGIDBinary(t *testing.T) {
	dir := t.TempDir()

	fakeBin := filepath.Join(dir, "sgidbin")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}
	if err := os.Chmod(fakeBin, 0o2755); err != nil {
		t.Fatalf("failed to set SGID bit: %v", err)
	}

	// Verify the SGID bit was actually set; some filesystems silently drop it.
	info, err := os.Lstat(fakeBin)
	if err != nil {
		t.Fatalf("os.Lstat failed: %v", err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Skip("setgid bit could not be set in this environment (likely a restricted filesystem); skipping test")
	}

	s := filesystem.NewIntegrityScanner()
	opts := scanner.ScanOptions{
		TargetPaths: []string{dir},
	}

	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for SGID binary, got none")
	}
}

// ---------------------------------------------------------------------------
// Stub scanners — interface tests
// ---------------------------------------------------------------------------

func TestAnomaliesScanner_Interface(t *testing.T) {
	s := filesystem.NewAnomaliesScanner()

	if s.Name() != "filesystem" {
		t.Errorf("Name() = %q, want %q", s.Name(), "filesystem")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	// Scan must not return an error; findings depend on environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

func TestTimestompScanner_Interface(t *testing.T) {
	s := filesystem.NewTimestompScanner()

	if s.Name() != "timestomp" {
		t.Errorf("Name() = %q, want %q", s.Name(), "timestomp")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	// Scan must not return an error; findings depend on environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

func TestCapabilitiesScanner_Interface(t *testing.T) {
	s := filesystem.NewCapabilitiesScanner()

	if s.Name() != "capabilities" {
		t.Errorf("Name() = %q, want %q", s.Name(), "capabilities")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	// Scan must not error; findings depend on environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

// TestCapabilitiesScanner_DetectsCapSetuid verifies that getcap output
// containing cap_setuid produces a CRITICAL finding.
func TestCapabilitiesScanner_DetectsCapSetuid(t *testing.T) {
	output := "/usr/bin/somebinary cap_setuid=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for cap_setuid, got none")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "capabilities" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
			if f.Location == "" {
				t.Error("finding has empty Location")
			}
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL finding for cap_setuid, got: %+v", findings)
	}
}

// TestCapabilitiesScanner_DetectsCapNetRaw verifies that cap_net_raw produces
// a HIGH finding.
func TestCapabilitiesScanner_DetectsCapNetRaw(t *testing.T) {
	output := "/usr/bin/ping cap_net_raw=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for cap_net_raw, got none")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Scanner == "capabilities" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a HIGH finding for cap_net_raw, got: %+v", findings)
	}
}

// TestCapabilitiesScanner_DetectsSuspiciousPath verifies that any capability
// on a binary in /tmp or /home produces a CRITICAL finding.
func TestCapabilitiesScanner_DetectsSuspiciousPath(t *testing.T) {
	output := "/tmp/evilbinary cap_net_raw=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for capability on /tmp binary, got none")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "capabilities" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL finding for /tmp binary with capability, got: %+v", findings)
	}
}

// TestCapabilitiesScanner_NoFindingsForUnknownCap verifies that an unknown or
// low-risk capability does not produce a finding.
func TestCapabilitiesScanner_NoFindingsForUnknownCap(t *testing.T) {
	output := "/usr/bin/somebinary cap_chown=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for cap_chown, got %d: %+v", len(findings), findings)
	}
}

func TestSwapScanner_Interface(t *testing.T) {
	s := filesystem.NewSwapScanner()

	if s.Name() != "swap" {
		t.Errorf("Name() = %q, want %q", s.Name(), "swap")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}

	// Scan must not return an error; findings depend on environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AnomaliesScanner — detection tests
// ---------------------------------------------------------------------------

// TestAnomaliesScanner_DetectsHiddenFileInSystemDir verifies that a hidden
// dotfile placed in a system binary directory produces a HIGH finding.
func TestAnomaliesScanner_DetectsHiddenFileInSystemDir(t *testing.T) {
	dir := t.TempDir()

	hiddenFile := filepath.Join(dir, ".hidden_evil")
	if err := os.WriteFile(hiddenFile, []byte("malware"), 0o644); err != nil {
		t.Fatalf("failed to create hidden file: %v", err)
	}

	s := filesystem.NewAnomaliesScannerWithDirs(nil, []string{dir}, nil)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for hidden file in system dir, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Scanner == "filesystem" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Location == "" {
				t.Error("finding has empty Location")
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for hidden file in system dir, got: %+v", findings)
	}
}

// TestAnomaliesScanner_DetectsWorldWritableDir verifies that a world-writable
// directory in the scan dirs produces a MEDIUM finding.
func TestAnomaliesScanner_DetectsWorldWritableDir(t *testing.T) {
	parent := t.TempDir()
	subDir := filepath.Join(parent, "writable_subdir")
	if err := os.Mkdir(subDir, 0o777); err != nil {
		t.Fatalf("failed to create world-writable dir: %v", err)
	}
	// Ensure umask doesn't strip the world-writable bit
	if err := os.Chmod(subDir, 0o777); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}

	s := filesystem.NewAnomaliesScannerWithDirs(nil, nil, []string{parent})
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for world-writable directory, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "filesystem" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for world-writable dir, got: %+v", findings)
	}
}

// TestAnomaliesScanner_DetectsHiddenDotfileInTmp verifies that a hidden
// dotfile in a tmp directory produces a MEDIUM finding.
func TestAnomaliesScanner_DetectsHiddenDotfileInTmp(t *testing.T) {
	dir := t.TempDir()

	hiddenFile := filepath.Join(dir, ".hidden")
	if err := os.WriteFile(hiddenFile, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to create hidden file: %v", err)
	}

	s := filesystem.NewAnomaliesScannerWithDirs([]string{dir}, nil, nil)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for hidden dotfile in tmp, got none")
	}

	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "filesystem" {
			t.Errorf("Scanner = %q, want filesystem", f.Scanner)
		}
	}
}

// ---------------------------------------------------------------------------
// TimestompScanner — detection tests
// ---------------------------------------------------------------------------

// TestTimestompScanner_DetectsFutureMtime verifies that a file with a
// modification time in the future produces a CRITICAL finding.
func TestTimestompScanner_DetectsFutureMtime(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "suspiciousbinary")
	if err := os.WriteFile(fakeBin, []byte("data"), 0o755); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Set mtime 1 hour in the future.
	futureTime := time.Now().Add(1 * time.Hour)
	if err := os.Chtimes(fakeBin, futureTime, futureTime); err != nil {
		t.Fatalf("failed to set future mtime: %v", err)
	}

	info, err := os.Stat(fakeBin)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}

	findings := filesystem.CheckTimestomp(fakeBin, info)
	if len(findings) == 0 {
		t.Fatal("expected a CRITICAL finding for future mtime, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical && f.Scanner == "timestomp" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for future mtime, got: %+v", findings)
	}
}

// TestTimestompScanner_NoFindingForNormalFile verifies that a file with
// normal timestamps does not produce any CRITICAL findings.
func TestTimestompScanner_NoFindingForNormalFile(t *testing.T) {
	dir := t.TempDir()
	normalFile := filepath.Join(dir, "normal")
	if err := os.WriteFile(normalFile, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	info, err := os.Stat(normalFile)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}

	findings := filesystem.CheckTimestomp(normalFile, info)
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			t.Errorf("unexpected CRITICAL finding for normal file: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// SwapScanner — detection tests
// ---------------------------------------------------------------------------

// TestSwapScanner_ScanDoesNotError verifies that Scan completes without error.
func TestSwapScanner_ScanDoesNotError(t *testing.T) {
	s := filesystem.NewSwapScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestEncryptionScanner_Interface(t *testing.T) {
	s := filesystem.NewEncryptionScanner()

	if s.Name() != "encryption" {
		t.Errorf("Name() = %q, want %q", s.Name(), "encryption")
	}
	if s.Category() != "filesystem" {
		t.Errorf("Category() = %q, want %q", s.Category(), "filesystem")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should be nil")
	}

	var _ scanner.Scanner = s
}

func TestEncryptionScanner_DoesNotPanic(t *testing.T) {
	s := filesystem.NewEncryptionScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// TestEncryptionScanner_DetectsUnencryptedRoot creates fake /proc/mounts
// content with a plain /dev/sda1 root device and verifies a MEDIUM finding.
func TestEncryptionScanner_DetectsUnencryptedRoot(t *testing.T) {
	dir := t.TempDir()

	mountsContent := "/dev/sda1 / ext4 rw,relatime 0 0\n"
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte(mountsContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, filepath.Join(dir, "sysblock"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "encryption" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for unencrypted root, got: %+v", findings)
	}
}

// TestEncryptionScanner_NoFindingForDMCryptRoot verifies that a /dev/dm-0
// root device produces no finding (dm devices are accepted as encrypted).
func TestEncryptionScanner_NoFindingForDMCryptRoot(t *testing.T) {
	dir := t.TempDir()

	mountsContent := "/dev/dm-0 / ext4 rw,relatime 0 0\n"
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte(mountsContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, filepath.Join(dir, "sysblock"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Root filesystem does not appear to be encrypted" {
			t.Errorf("unexpected root encryption finding for dm-crypt device: %+v", f)
		}
	}
}
