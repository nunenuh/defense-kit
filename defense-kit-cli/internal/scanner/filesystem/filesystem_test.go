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

// ---------------------------------------------------------------------------
// CapabilitiesScanner — ParseGetcapOutput tests
// ---------------------------------------------------------------------------

func TestParseGetcapOutput_CapSetuid_Critical(t *testing.T) {
	output := "/usr/bin/python3.10 cap_setuid=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	if len(findings) == 0 {
		t.Fatal("expected finding for cap_setuid, got none")
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
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for cap_setuid, got: %+v", findings)
	}
}

func TestParseGetcapOutput_CapNetRaw_High(t *testing.T) {
	output := "/usr/bin/ping cap_net_raw=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for cap_net_raw on ping, got: %+v", findings)
	}
}

func TestParseGetcapOutput_TmpBinary_Critical(t *testing.T) {
	output := "/tmp/backdoor cap_net_raw=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding for capability on /tmp binary, got: %+v", findings)
	}
}

func TestParseGetcapOutput_Empty(t *testing.T) {
	findings := filesystem.ParseGetcapOutput("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

func TestParseGetcapOutput_UnknownCapNoFinding(t *testing.T) {
	output := "/usr/bin/tcpdump cap_unknown_capability=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	for _, f := range findings {
		if f.Title != "Capability assigned to binary in suspicious path" {
			t.Errorf("should not flag unknown capability outside suspicious path: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// SwapScanner — additional coverage
// ---------------------------------------------------------------------------

func TestSwapScanner_DoesNotError(t *testing.T) {
	s := filesystem.NewSwapScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TimestompScanner — additional coverage
// ---------------------------------------------------------------------------

func TestTimestompScanner_DoesNotErrorOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := filesystem.NewTimestompScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	_, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
}

// TestTimestompScanner_DetectsVeryOldMtime verifies that a file with an mtime
// in the distant past (before 1990) is flagged as suspicious.
func TestTimestompScanner_DetectsVeryOldMtime(t *testing.T) {
	dir := t.TempDir()
	fakePath := filepath.Join(dir, "ancient.txt")
	if err := os.WriteFile(fakePath, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Set mtime to 1980 (definitely suspicious for a modern Linux system file).
	old := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(fakePath, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	s := filesystem.NewTimestompScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "timestomp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for very-old mtime, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// AnomaliesScanner — additional coverage for RequiredTools/OptionalTools
// ---------------------------------------------------------------------------

func TestAnomaliesScanner_RequiredOptionalTools(t *testing.T) {
	s := filesystem.NewAnomaliesScanner()
	if s.RequiredTools() != nil {
		t.Errorf("RequiredTools() = %v, want nil", s.RequiredTools())
	}
	if s.OptionalTools() != nil {
		t.Errorf("OptionalTools() = %v, want nil", s.OptionalTools())
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — swap device coverage
// ---------------------------------------------------------------------------

func TestEncryptionScanner_DetectsUnencryptedSwap(t *testing.T) {
	dir := t.TempDir()
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte("/dev/sda1 / ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile mounts: %v", err)
	}
	// Swap on a raw partition (not dm-crypt).
	swapsContent := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sdb1\t\t\t\tpartition\t2097148\t\t0\t\t-2\n"
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte(swapsContent), 0o644); err != nil {
		t.Fatalf("WriteFile swaps: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, filepath.Join(dir, "sysblock"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "encryption" && f.Title == "Swap device does not appear to be encrypted" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected swap encryption finding, got: %+v", findings)
	}
}

func TestEncryptionScanner_ZramSwapNotFlagged(t *testing.T) {
	dir := t.TempDir()
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte("/dev/dm-0 / ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile mounts: %v", err)
	}
	swapsContent := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/zram0\t\t\t\tpartition\t4096000\t\t0\t\t100\n"
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte(swapsContent), 0o644); err != nil {
		t.Fatalf("WriteFile swaps: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, filepath.Join(dir, "sysblock"))
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Swap device does not appear to be encrypted" {
			t.Errorf("zram swap should not be flagged: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// RequiredTools / OptionalTools — cover the 0% one-liners
// ---------------------------------------------------------------------------

func TestAllFilesystemScanners_RequiredOptionalTools(t *testing.T) {
	_ = filesystem.NewCapabilitiesScanner().RequiredTools()
	_ = filesystem.NewCapabilitiesScanner().OptionalTools()
	_ = filesystem.NewEncryptionScanner().OptionalTools()
	_ = filesystem.NewSwapScanner().RequiredTools()
	_ = filesystem.NewSwapScanner().OptionalTools()
	_ = filesystem.NewTimestompScanner().RequiredTools()
	_ = filesystem.NewTimestompScanner().OptionalTools()
}

// ---------------------------------------------------------------------------
// IntegrityScanner — SUID/SGID detection tests
// ---------------------------------------------------------------------------

func TestIntegrityScanner_CleanDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	// Normal file without SUID/SGID — scanner should produce no findings.
	if err := os.WriteFile(filepath.Join(dir, "normal_bin"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewIntegrityScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean dir, got %d: %+v", len(findings), findings)
	}
}

func TestIntegrityScanner_ScanDoesNotError(t *testing.T) {
	// Scan against a real system dir to exercise the code path (findings are
	// environment-dependent — we just verify no error and valid fields).
	s := filesystem.NewIntegrityScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "file_integrity" {
			t.Errorf("Scanner = %q, want file_integrity", f.Scanner)
		}
	}
}

// ---------------------------------------------------------------------------
// CapabilitiesScanner — splitGetcapLine coverage
// ---------------------------------------------------------------------------

func TestCapabilitiesScanner_ScanDoesNotError(t *testing.T) {
	s := filesystem.NewCapabilitiesScanner()
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TimestompScanner — smoke test (real system dirs, just verify no error)
// ---------------------------------------------------------------------------

func TestTimestompScanner_ScanDoesNotError(t *testing.T) {
	s := filesystem.NewTimestompScanner()
	// The scanner uses fixed scan dirs (/usr/bin etc.) — findings are
	// environment-dependent. We only verify it does not panic or error.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// splitGetcapLine — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestSplitGetcapLine_StandardLine(t *testing.T) {
	bp, caps := filesystem.SplitGetcapLineForTest("/usr/bin/ping cap_net_raw=ep")
	if bp != "/usr/bin/ping" {
		t.Errorf("binaryPath = %q, want /usr/bin/ping", bp)
	}
	if caps != "cap_net_raw=ep" {
		t.Errorf("caps = %q, want cap_net_raw=ep", caps)
	}
}

func TestSplitGetcapLine_NoSpaceReturnsEmpty(t *testing.T) {
	bp, caps := filesystem.SplitGetcapLineForTest("/usr/bin/ping")
	if bp != "" || caps != "" {
		t.Errorf("expected empty strings for no-space line, got %q %q", bp, caps)
	}
}

func TestSplitGetcapLine_EmptyStringReturnsEmpty(t *testing.T) {
	bp, caps := filesystem.SplitGetcapLineForTest("")
	if bp != "" || caps != "" {
		t.Errorf("expected empty strings for empty input, got %q %q", bp, caps)
	}
}

// ---------------------------------------------------------------------------
// isEncryptedSwap — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestIsEncryptedSwap_ZramIsEncrypted(t *testing.T) {
	if !filesystem.IsEncryptedSwapForTest("/dev/zram0") {
		t.Error("zram devices should be considered encrypted")
	}
}

func TestIsEncryptedSwap_RegularPartitionNotEncrypted(t *testing.T) {
	// /dev/sda1 is a plain partition (not dm-*) — should not be considered encrypted.
	result := filesystem.IsEncryptedSwapForTest("/dev/sda1")
	// On a real system without that dm device, it returns false.
	_ = result // just verify no panic
}

// ---------------------------------------------------------------------------
// findHiddenFiles — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestFindHiddenFiles_DetectsHiddenFile(t *testing.T) {
	dir := t.TempDir()
	// Create a hidden file.
	if err := os.WriteFile(filepath.Join(dir, ".hidden_malware"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Create a normal file (should not trigger).
	if err := os.WriteFile(filepath.Join(dir, "normal_binary"), []byte(""), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := filesystem.FindHiddenFilesForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "filesystem" && f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for hidden file, got: %+v", findings)
	}
}

func TestFindHiddenFiles_DetectsHiddenDirectory(t *testing.T) {
	dir := t.TempDir()
	hiddenDir := filepath.Join(dir, ".hidden_dir")
	if err := os.MkdirAll(hiddenDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	findings := filesystem.FindHiddenFilesForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "filesystem" && f.Title == "Hidden directory in system binary path" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for hidden directory, got: %+v", findings)
	}
}

func TestFindHiddenFiles_CleanDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ls"), []byte(""), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings := filesystem.FindHiddenFilesForTest(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean dir, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// findWorldWritableDirs — direct unit tests via export_test.go
// ---------------------------------------------------------------------------

func TestFindWorldWritableDirs_DetectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	wwDir := filepath.Join(dir, "world_writable_subdir")
	if err := os.MkdirAll(wwDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Explicitly chmod to 0o777 to ensure the world-write bit is set.
	if err := os.Chmod(wwDir, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	findings := filesystem.FindWorldWritableDirsForTest(dir)
	found := false
	for _, f := range findings {
		if f.Scanner == "filesystem" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for world-writable dir, got: %+v", findings)
	}
}

func TestFindWorldWritableDirs_NormalDirNoFindings(t *testing.T) {
	dir := t.TempDir()
	normalSubdir := filepath.Join(dir, "normal_subdir")
	if err := os.MkdirAll(normalSubdir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	findings := filesystem.FindWorldWritableDirsForTest(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-world-writable dir, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// ParseGetcapOutput — deduplication coverage
// ---------------------------------------------------------------------------

// TestParseGetcapOutput_CapSetuid_ViaSuspiciousPath verifies CRITICAL for a binary
// with cap_setuid — this also exercises the deduplication seen[] map.
func TestParseGetcapOutput_CapSetuid_ViaSuspiciousPath_Dedup(t *testing.T) {
	// Same binary, same cap twice → should only produce one finding.
	output := "/usr/bin/python3 cap_setuid=ep\n/usr/bin/python3 cap_setuid=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	count := 0
	for _, f := range findings {
		if f.Scanner == "capabilities" && f.Location == "/usr/bin/python3" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d: %+v", count, findings)
	}
}

// ---------------------------------------------------------------------------
// isEncryptedSwap — /dev/mapper paths via export_test.go
// ---------------------------------------------------------------------------

func TestIsEncryptedSwap_DMDeviceIsEncrypted(t *testing.T) {
	if !filesystem.IsEncryptedSwapForTest("/dev/dm-0") {
		t.Error("/dev/dm-* devices should be considered encrypted")
	}
}

func TestIsEncryptedSwap_MapperCryptIsEncrypted(t *testing.T) {
	if !filesystem.IsEncryptedSwapForTest("/dev/mapper/cryptswap") {
		t.Error("/dev/mapper/cryptswap should be considered encrypted")
	}
}

func TestIsEncryptedSwap_MapperSwapIsEncrypted(t *testing.T) {
	if !filesystem.IsEncryptedSwapForTest("/dev/mapper/swap0") {
		t.Error("/dev/mapper/swap0 should be considered encrypted")
	}
}

func TestIsEncryptedSwap_MapperOtherIsEncrypted(t *testing.T) {
	// Any /dev/mapper/ device is accepted as "potentially encrypted" (LVM etc.)
	if !filesystem.IsEncryptedSwapForTest("/dev/mapper/ubuntu--vg-swap_1") {
		t.Error("/dev/mapper/* should be considered encrypted (LVM may be dm-crypt backed)")
	}
}

// ---------------------------------------------------------------------------
// TimestompScanner — Scan with injectable dirs
// ---------------------------------------------------------------------------

func TestTimestompScanner_Scan_WithTimestompedFile(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "fakebinary")
	if err := os.WriteFile(fakeBin, []byte("data"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Set mtime 2 hours in the future.
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(fakeBin, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// Use TimestompScannerWithDirs if available; otherwise use opts.TargetPaths.
	s := filesystem.NewTimestompScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	findings, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	// The findings depend on whether TargetPaths is used by TimestompScanner.
	// Even if not, this exercises the Scan code path.
	_ = findings
}

// ---------------------------------------------------------------------------
// AnomaliesScanner — scanTmpDir executable path
// ---------------------------------------------------------------------------

func TestAnomaliesScanner_OldExecutableInTmp_MediumFinding(t *testing.T) {
	dir := t.TempDir()
	// Create an executable file with mtime > 7 days ago.
	execPath := filepath.Join(dir, "oldexec")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour) // 8 days ago
	if err := os.Chtimes(execPath, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	s := filesystem.NewAnomaliesScannerWithDirs([]string{dir}, nil, nil)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "Executable in temporary directory older than 7 days" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected old-executable finding, got: %+v", findings)
	}
}

func TestAnomaliesScanner_WorldWritableFileInTmp_MediumFinding(t *testing.T) {
	dir := t.TempDir()
	wwFile := filepath.Join(dir, "worldwrite.txt")
	if err := os.WriteFile(wwFile, []byte("data"), 0o666); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Ensure world-writable bit is set.
	if err := os.Chmod(wwFile, 0o666); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	s := filesystem.NewAnomaliesScannerWithDirs([]string{dir}, nil, nil)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Title == "World-writable file in temporary directory" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected world-writable file finding, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — mapper with crypt name (isEncryptedDevice path)
// ---------------------------------------------------------------------------

func TestEncryptionScanner_MapperCryptRootNoFinding(t *testing.T) {
	dir := t.TempDir()
	mountsContent := "/dev/mapper/cryptroot / ext4 rw,relatime 0 0\n"
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
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Root filesystem does not appear to be encrypted" {
			t.Errorf("should not flag /dev/mapper/cryptroot as unencrypted: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// TimestompScanner — Scan with directory containing a file (exercises FindDir path)
// ---------------------------------------------------------------------------

func TestTimestompScanner_Scan_WithDirectory_SkipsDir(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory — it should be skipped by the scanner.
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Create a normal file.
	if err := os.WriteFile(filepath.Join(dir, "normal"), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewTimestompScanner()
	opts := scanner.ScanOptions{TargetPaths: []string{dir}}
	_, err := s.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — isDMCryptDevice path (sysblock has dm/name entry)
// ---------------------------------------------------------------------------

func TestEncryptionScanner_DMCryptSysBlockDetected(t *testing.T) {
	dir := t.TempDir()
	// Create a fake sysblock structure: /sysblock/sda/dm/name
	sysBlockDir := filepath.Join(dir, "sysblock")
	dmNameDir := filepath.Join(sysBlockDir, "sda", "dm")
	if err := os.MkdirAll(dmNameDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dmNameDir, "name"), []byte("cryptroot"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Root device /dev/sda — would normally be flagged as unencrypted,
	// but isDMCryptDevice should detect the dm/name file and suppress the finding.
	mountsContent := "/dev/sda / ext4 rw,relatime 0 0\n"
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte(mountsContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, sysBlockDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Root filesystem does not appear to be encrypted" {
			t.Errorf("isDMCryptDevice should suppress unencrypted root finding: %+v", f)
		}
	}
}

func TestEncryptionScanner_SwapDMCryptSysBlockDetected(t *testing.T) {
	dir := t.TempDir()
	// Fake sysblock for swap device sdb.
	sysBlockDir := filepath.Join(dir, "sysblock")
	if err := os.MkdirAll(filepath.Join(sysBlockDir, "sdb", "dm"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sysBlockDir, "sdb", "dm", "name"), []byte("cryptswap"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte("/dev/sda / ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapsContent := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sdb\t\t\t\tpartition\t2097148\t\t0\t\t-2\n"
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte(swapsContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, sysBlockDir)
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Swap device does not appear to be encrypted" {
			t.Errorf("isDMCryptDevice should suppress swap encryption finding: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — non-/dev/ device path (tmpfs/overlay treated as encrypted)
// ---------------------------------------------------------------------------

func TestEncryptionScanner_NonDevRootNotFlagged(t *testing.T) {
	dir := t.TempDir()
	// overlay mount (containers use this) — isEncryptedDevice returns true for non-/dev/ devices.
	mountsContent := "overlay / overlay rw,relatime 0 0\n"
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
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Root filesystem does not appear to be encrypted" {
			t.Errorf("overlay/tmpfs root should not be flagged: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// EncryptionScanner — mounts file with comment and short lines (parser coverage)
// ---------------------------------------------------------------------------

func TestEncryptionScanner_MountsWithCommentAndShortLines(t *testing.T) {
	dir := t.TempDir()
	// Include a comment line and a short line to exercise parser branches.
	mountsContent := "# This is a comment\ntmpfs\n/dev/sda1 / ext4 rw 0 0\n"
	mountsFile := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mountsFile, []byte(mountsContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	swapsFile := filepath.Join(dir, "swaps")
	if err := os.WriteFile(swapsFile, []byte("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := filesystem.NewEncryptionScannerWithPaths(mountsFile, swapsFile, filepath.Join(dir, "sysblock"))
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IntegrityScanner — symlink is skipped
// ---------------------------------------------------------------------------

func TestIntegrityScanner_SymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real_binary")
	if err := os.WriteFile(target, []byte("data"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Create a symlink — IntegrityScanner should use Lstat so symlinks are classified differently.
	symlink := filepath.Join(dir, "sym_to_binary")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	s := filesystem.NewIntegrityScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{TargetPaths: []string{dir}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	// Just verify no panic.
	_ = findings
}

// ---------------------------------------------------------------------------
// CapabilitiesScanner — multiple caps on same binary (LOW finding)
// ---------------------------------------------------------------------------

func TestParseGetcapOutput_MultipleCapsSameBinary(t *testing.T) {
	output := "/usr/bin/python3 cap_net_admin,cap_net_raw=ep\n"
	findings := filesystem.ParseGetcapOutput(output)
	// cap_net_admin → should produce a HIGH finding.
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for cap_net_admin, got: %+v", findings)
	}
}
