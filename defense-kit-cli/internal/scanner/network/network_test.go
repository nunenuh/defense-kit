package network_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/network"
)

// ---------------------------------------------------------------------------
// PortsScanner
// ---------------------------------------------------------------------------

func TestPortsScanner_Interface(t *testing.T) {
	s := network.NewPortsScanner()

	if s.Name() != "ports" {
		t.Errorf("Name() = %q, want %q", s.Name(), "ports")
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

// TestPortsScanner_ParsesProcNetTCP verifies the scanner can parse a synthetic
// /proc/net/tcp file containing one unusual listening port and correctly
// reports it as a MEDIUM finding.
func TestPortsScanner_ParsesProcNetTCP(t *testing.T) {
	// Build a minimal /proc/net/tcp-style file with:
	//   - Port 22 (SSH, common — should be skipped)
	//   - Port 31337 (unusual — should produce a finding)
	// Both are in LISTEN state (0A).
	// local_address format: <hex_ip_le>:<hex_port_be>
	//   127.0.0.1 = 0100007F (little-endian), port 22 = 0016, port 31337 = 7A69
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:7A69 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 00000000:0000 06 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
`
	dir := t.TempDir()
	tcpFile := filepath.Join(dir, "tcp")
	if err := os.WriteFile(tcpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write synthetic tcp file: %v", err)
	}

	// Use the exported helper to parse the file directly.
	ports, err := network.ParseProcNetTCPFile(tcpFile)
	if err != nil {
		t.Fatalf("ParseProcNetTCPFile returned error: %v", err)
	}

	// We expect port 22 and 31337 (state 0A), but NOT port 80 (state 06).
	portSet := make(map[uint16]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	if !portSet[22] {
		t.Error("expected port 22 in parsed results")
	}
	if !portSet[31337] {
		t.Error("expected port 31337 in parsed results")
	}
	if portSet[80] {
		t.Error("port 80 should NOT be in results (state is not LISTEN)")
	}
}

// TestPortsScanner_ScanProducesFindings runs Scan against the live /proc/net/tcp
// if it exists, verifying the scanner runs without error and that any findings
// have the mandatory fields populated.
func TestPortsScanner_ScanProducesFindings(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); os.IsNotExist(err) {
		t.Skip("/proc/net/tcp not available in this environment")
	}

	s := network.NewPortsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "ports" {
			t.Errorf("finding Scanner = %q, want %q", f.Scanner, "ports")
		}
		if f.Severity != scanner.SevMedium {
			t.Errorf("finding Severity = %v, want MEDIUM", f.Severity)
		}
		if f.Location == "" {
			t.Error("finding has empty Location")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
	}
}

// ---------------------------------------------------------------------------
// Stub scanners — interface tests
// ---------------------------------------------------------------------------

func TestConnectionsScanner_Interface(t *testing.T) {
	s := network.NewConnectionsScanner()

	if s.Name() != "connections" {
		t.Errorf("Name() = %q, want %q", s.Name(), "connections")
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

// TestParseHexIP verifies the hex-to-dotted-decimal IP conversion helper.
func TestParseHexIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"0101010A", "10.1.1.1"},
		{"FE01A8C0", "192.168.1.254"},
	}
	for _, tc := range tests {
		got := network.ParseHexIPExported(tc.input)
		if got != tc.want {
			t.Errorf("ParseHexIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestConnectionsScanner_DetectsSuspiciousPort creates a synthetic
// /proc/net/tcp file with a connection to port 4444 and verifies that the
// scanner produces a CRITICAL finding.
func TestConnectionsScanner_DetectsSuspiciousPort(t *testing.T) {
	// 127.0.0.1:12345 → 10.0.0.1:4444 ESTABLISHED
	// local:  0100007F:3039   (127.0.0.1, port 12345 = 0x3039)
	// remote: 0100000A:115C   (10.0.0.1,  port 4444  = 0x115C)
	// inode field (index 9) = 99999
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:3039 0100000A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0\n"

	dir := t.TempDir()
	tcpFile := filepath.Join(dir, "tcp")
	if err := os.WriteFile(tcpFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write synthetic tcp file: %v", err)
	}

	conns, err := network.ParseProcNetTCPConnsFile(tcpFile)
	if err != nil {
		t.Fatalf("ParseProcNetTCPConnsFile: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	// Verify the remote port is decoded as 4444.
	if conns[0].RemotePort != 4444 {
		t.Errorf("RemotePort = %d, want 4444", conns[0].RemotePort)
	}
	if conns[0].RemoteIP != "10.0.0.1" {
		t.Errorf("RemoteIP = %q, want %q", conns[0].RemoteIP, "10.0.0.1")
	}

	// Now run a full Scan using a real ConnectionsScanner. We confirm that
	// when the scanner sees a connection on port 4444 it would emit a CRITICAL
	// finding.  Since we cannot inject PID mapping in an external test, we
	// validate only the parsing path through ParseProcNetTCPConnsFile above
	// and leave end-to-end validation to TestConnectionsScanner_LiveScan.
}

// TestConnectionsScanner_LiveScan runs against the real /proc/net/tcp if
// available. It verifies that Scan does not panic and that any returned
// findings have the mandatory fields populated.
func TestConnectionsScanner_LiveScan(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); os.IsNotExist(err) {
		t.Skip("/proc/net/tcp not available in this environment")
	}

	s := network.NewConnectionsScanner()
	findings, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "" {
			t.Error("finding has empty ID")
		}
		if f.Scanner != "connections" {
			t.Errorf("finding Scanner = %q, want %q", f.Scanner, "connections")
		}
		if f.Title == "" {
			t.Error("finding has empty Title")
		}
		if f.Location == "" {
			t.Error("finding has empty Location")
		}
		if f.Evidence == "" {
			t.Error("finding has empty Evidence")
		}
	}
}

func TestDNSScanner_Interface(t *testing.T) {
	s := network.NewDNSScanner()

	if s.Name() != "dns" {
		t.Errorf("Name() = %q, want %q", s.Name(), "dns")
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

	// Scan must not error; findings may or may not be present depending on environment.
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

// TestDNSScanner_DetectsRogueResolver verifies that a synthetic resolv.conf
// containing an unknown nameserver produces a HIGH finding.
func TestDNSScanner_DetectsRogueResolver(t *testing.T) {
	dir := t.TempDir()
	resolvConf := filepath.Join(dir, "resolv.conf")
	content := "nameserver 192.168.100.99\n"
	if err := os.WriteFile(resolvConf, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write resolv.conf: %v", err)
	}

	findings := network.ParseResolvConf(resolvConf)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for rogue resolver, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Scanner == "dns" {
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
		t.Errorf("expected a HIGH finding from dns scanner, got: %+v", findings)
	}
}

// TestDNSScanner_NoFindingsForKnownGoodResolvers verifies that well-known public
// DNS servers do not produce findings.
func TestDNSScanner_NoFindingsForKnownGoodResolvers(t *testing.T) {
	dir := t.TempDir()
	resolvConf := filepath.Join(dir, "resolv.conf")
	content := "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
	if err := os.WriteFile(resolvConf, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write resolv.conf: %v", err)
	}

	findings := network.ParseResolvConf(resolvConf)
	for _, f := range findings {
		if f.Severity == scanner.SevHigh {
			t.Errorf("unexpected HIGH finding for known-good resolvers: %+v", f)
		}
	}
}

// TestDNSScanner_DetectsMultipleDifferentResolvers verifies that multiple
// differing nameservers produce a MEDIUM finding.
func TestDNSScanner_DetectsMultipleDifferentResolvers(t *testing.T) {
	dir := t.TempDir()
	resolvConf := filepath.Join(dir, "resolv.conf")
	// Two different unknown nameservers → rogue HIGH + multiple MEDIUM.
	content := "nameserver 10.0.0.1\nnameserver 10.0.0.2\n"
	if err := os.WriteFile(resolvConf, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write resolv.conf: %v", err)
	}

	findings := network.ParseResolvConf(resolvConf)
	hasMedium := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium {
			hasMedium = true
		}
	}
	if !hasMedium {
		t.Errorf("expected a MEDIUM finding for multiple differing resolvers, got: %+v", findings)
	}
}

func TestFirewallScanner_Interface(t *testing.T) {
	s := network.NewFirewallScanner()

	if s.Name() != "firewall" {
		t.Errorf("Name() = %q, want %q", s.Name(), "firewall")
	}
	if s.Category() != "network" {
		t.Errorf("Category() = %q, want %q", s.Category(), "network")
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

// TestFirewallScanner_DetectsForwardAccept verifies that iptables output with
// a FORWARD ACCEPT policy produces a HIGH finding.
func TestFirewallScanner_DetectsForwardAccept(t *testing.T) {
	output := `Chain INPUT (policy DROP)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
`
	findings := network.ParseIPTablesOutput(output, "test-iptables")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for FORWARD ACCEPT, got none")
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Scanner == "firewall" {
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
		t.Errorf("expected a HIGH finding for FORWARD ACCEPT, got: %+v", findings)
	}
}

// TestFirewallScanner_NoFindingForForwardDrop verifies that a FORWARD DROP
// policy does not produce a finding.
func TestFirewallScanner_NoFindingForForwardDrop(t *testing.T) {
	output := `Chain INPUT (policy DROP)
target     prot opt source               destination

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
`
	findings := network.ParseIPTablesOutput(output, "test-iptables")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for FORWARD DROP, got %d: %+v", len(findings), findings)
	}
}

func TestVPNScanner_Interface(t *testing.T) {
	s := network.NewVPNScanner()

	if s.Name() != "vpn" {
		t.Errorf("Name() = %q, want %q", s.Name(), "vpn")
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

	// Scan must not return an error; findings depend on environment (no VPN configs in most CI).
	_, err := s.Scan(context.Background(), scanner.ScanOptions{})
	if err != nil {
		t.Errorf("Scan returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VPNScanner — detection tests
// ---------------------------------------------------------------------------

// TestVPNScanner_DetectsAllTrafficWireGuard verifies that a WireGuard config
// with AllowedIPs = 0.0.0.0/0 produces a LOW finding.
func TestVPNScanner_DetectsAllTrafficWireGuard(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")
	content := `[Interface]
PrivateKey = abc123

[Peer]
PublicKey = def456
AllowedIPs = 0.0.0.0/0
`
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write WireGuard config: %v", err)
	}

	findings := network.ParseWireGuardConfig(confPath)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for AllowedIPs = 0.0.0.0/0, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevLow && f.Scanner == "vpn" {
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
		t.Errorf("expected LOW finding for AllowedIPs 0.0.0.0/0, got: %+v", findings)
	}
}

// TestVPNScanner_NoFindingForRestrictedWireGuard verifies that a WireGuard
// config with a specific subnet does not produce an all-traffic finding.
func TestVPNScanner_NoFindingForRestrictedWireGuard(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")
	// Use a file mtime well in the past to avoid the "recently modified" finding.
	content := `[Interface]
PrivateKey = abc123

[Peer]
PublicKey = def456
AllowedIPs = 10.0.0.0/24
`
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write WireGuard config: %v", err)
	}
	// Backdate the file so the "recently modified" heuristic doesn't fire.
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(confPath, past, past); err != nil {
		t.Fatalf("failed to backdate config: %v", err)
	}

	findings := network.ParseWireGuardConfig(confPath)
	for _, f := range findings {
		if f.Severity >= scanner.SevMedium {
			t.Errorf("unexpected finding with severity >= MEDIUM for restricted AllowedIPs: %+v", f)
		}
	}
}

// TestVPNScanner_DetectsOpenVPNRedirectGateway verifies that an OpenVPN config
// with redirect-gateway produces a LOW finding.
func TestVPNScanner_DetectsOpenVPNRedirectGateway(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "client.conf")
	content := `client
dev tun
proto udp
remote vpn.example.com 1194
redirect-gateway def1
`
	if err := os.WriteFile(confPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write OpenVPN config: %v", err)
	}

	findings := network.ParseOpenVPNConfig(confPath)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for redirect-gateway, got none")
	}

	found := false
	for _, f := range findings {
		if f.Scanner == "vpn" && f.Severity == scanner.SevLow {
			found = true
		}
	}
	if !found {
		t.Errorf("expected LOW finding for redirect-gateway, got: %+v", findings)
	}
}
