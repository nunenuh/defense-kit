package network_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/network"
)

// ---------------------------------------------------------------------------
// ThreatIntelScanner — interface tests
// ---------------------------------------------------------------------------

func TestThreatIntelScanner_Interface(t *testing.T) {
	s := network.NewThreatIntelScanner()

	if s.Name() != "threat_intel" {
		t.Errorf("Name() = %q, want %q", s.Name(), "threat_intel")
	}
	if s.Category() != "network" {
		t.Errorf("Category() = %q, want %q", s.Category(), "network")
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
	if s.RequiredTools() != nil {
		t.Error("RequiredTools() should return nil")
	}
	if s.OptionalTools() != nil {
		t.Error("OptionalTools() should return nil")
	}
}

// ---------------------------------------------------------------------------
// ThreatIntelScanner — IP range matching
// ---------------------------------------------------------------------------

// TestThreatIntelScanner_MatchesKnownBadRange verifies that a connection to
// an IP in a known-bad range produces a CRITICAL finding.
func TestThreatIntelScanner_MatchesKnownBadRange(t *testing.T) {
	// 198.51.100.5 is in the TEST-NET-2 range (198.51.100.0/24).
	// Encode 198.51.100.5:80 as a /proc/net/tcp ESTABLISHED entry.
	// local:  0100007F:D431  (127.0.0.1, port 54321)
	// remote: 056433C6:0050  (198.51.100.5, port 80)
	//
	// Hex encoding for 198.51.100.5 in little-endian:
	//   198=0xC6  51=0x33  100=0x64  5=0x05  → "056433C6"
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D431 056433C6:0050 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0\n"

	dir := t.TempDir()
	tcpFile := filepath.Join(dir, "tcp")
	if err := os.WriteFile(tcpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write tcp file: %v", err)
	}

	// Empty resolv.conf so we only get connection findings.
	resolvFile := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvFile, []byte(""), 0o644); err != nil {
		t.Fatalf("write resolv.conf: %v", err)
	}

	s := network.ThreatIntelScannerWithOverrides(
		[]string{tcpFile},
		resolvFile,
		[]string{"198.51.100.0/24"},
		nil,
	)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one CRITICAL finding for known-bad IP, got none")
	}

	for _, f := range findings {
		if f.Severity != scanner.SevCritical {
			t.Errorf("expected CRITICAL severity, got %v", f.Severity)
		}
		if f.Scanner != "threat_intel" {
			t.Errorf("Scanner = %q, want %q", f.Scanner, "threat_intel")
		}
		if f.Metadata["matched_list"] == "" {
			t.Error("metadata matched_list should not be empty")
		}
		if f.Metadata["threat_type"] == "" {
			t.Error("metadata threat_type should not be empty")
		}
		if f.ID == "" {
			t.Error("finding ID should not be empty")
		}
	}
}

// TestThreatIntelScanner_NoFindingForSafeIP verifies that a connection to a
// non-malicious IP produces no threat intel finding.
func TestThreatIntelScanner_NoFindingForSafeIP(t *testing.T) {
	// 8.8.8.8:53 — Google DNS, safe.
	// Hex: 08080808 little-endian = 08080808, port 53 = 0035
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D432 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0\n"

	dir := t.TempDir()
	tcpFile := filepath.Join(dir, "tcp")
	if err := os.WriteFile(tcpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write tcp file: %v", err)
	}
	resolvFile := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvFile, []byte("nameserver 8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("write resolv.conf: %v", err)
	}

	s := network.ThreatIntelScannerWithOverrides(
		[]string{tcpFile},
		resolvFile,
		[]string{"198.51.100.0/24"}, // only TEST-NET-2 is bad
		nil,
	)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == scanner.SevCritical {
			t.Errorf("unexpected CRITICAL finding for safe IP 8.8.8.8: %+v", f)
		}
	}
}

// TestThreatIntelScanner_DetectsMaliciousNameserver verifies that a resolv.conf
// whose nameserver IP falls in a known-bad range produces a CRITICAL finding.
func TestThreatIntelScanner_DetectsMaliciousNameserver(t *testing.T) {
	dir := t.TempDir()
	tcpFile := filepath.Join(dir, "tcp")
	// Empty tcp file — no connections.
	if err := os.WriteFile(tcpFile, []byte("  sl  local_address rem_address   st tx_queue rx_queue\n"), 0o644); err != nil {
		t.Fatalf("write tcp file: %v", err)
	}

	// Nameserver in the known-bad range.
	resolvFile := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvFile, []byte("nameserver 203.0.113.10\n"), 0o644); err != nil {
		t.Fatalf("write resolv.conf: %v", err)
	}

	s := network.ThreatIntelScannerWithOverrides(
		[]string{tcpFile},
		resolvFile,
		[]string{"203.0.113.0/24"},
		nil,
	)

	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a CRITICAL finding for malicious nameserver, got none")
	}
	found := false
	for _, f := range findings {
		if f.Scanner == "threat_intel" && f.Severity == scanner.SevCritical {
			found = true
			if f.Metadata["nameserver"] == "" {
				t.Error("metadata nameserver should not be empty")
			}
		}
	}
	if !found {
		t.Errorf("expected CRITICAL finding from threat_intel, got: %+v", findings)
	}
}

// TestThreatIntelScanner_LiveScan ensures the scanner runs without error on
// the real system and that any findings have mandatory fields populated.
func TestThreatIntelScanner_LiveScan(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); os.IsNotExist(err) {
		t.Skip("/proc/net/tcp not available")
	}

	s := network.NewThreatIntelScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "threat_intel" {
			t.Errorf("Scanner = %q, want %q", f.Scanner, "threat_intel")
		}
		if f.Title == "" {
			t.Error("finding has empty Title")
		}
	}
}
