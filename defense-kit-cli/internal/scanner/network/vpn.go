package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// VPNScanner checks for active VPN tunnel interfaces and validates their
// configuration for potential misrouting or split-tunnel issues.
type VPNScanner struct {
	// wgConfDir is the directory holding WireGuard config files.
	wgConfDir string
	// ovpnConfDir is the directory holding OpenVPN config files.
	ovpnConfDir string
}

// NewVPNScanner creates a new VPNScanner.
func NewVPNScanner() *VPNScanner {
	return &VPNScanner{
		wgConfDir:   "/etc/wireguard",
		ovpnConfDir: "/etc/openvpn",
	}
}

// NewVPNScannerWithDirs creates a VPNScanner with custom config directories
// (used in tests).
func NewVPNScannerWithDirs(wgDir, ovpnDir string) *VPNScanner {
	return &VPNScanner{
		wgConfDir:   wgDir,
		ovpnConfDir: ovpnDir,
	}
}

func (s *VPNScanner) Name() string           { return "vpn" }
func (s *VPNScanner) Category() string       { return "network" }
func (s *VPNScanner) RequiresRoot() bool     { return false }
func (s *VPNScanner) RequiredTools() []string { return nil }
func (s *VPNScanner) OptionalTools() []string { return nil }
func (s *VPNScanner) Available() bool        { return true }
func (s *VPNScanner) Description() string {
	return "Checks for active VPN tunnel interfaces and validates their configuration for potential misrouting or split-tunnel issues."
}

// Scan checks WireGuard and OpenVPN configuration files for suspicious settings.
func (s *VPNScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.scanWireGuard()...)
	findings = append(findings, s.scanOpenVPN()...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// ParseWireGuardConfig parses a WireGuard config file and returns findings.
// Exported for testing with synthetic input.
func ParseWireGuardConfig(path string) []scanner.Finding {
	return parseWireGuardConfig(path)
}

// scanWireGuard scans all WireGuard config files in /etc/wireguard/.
func (s *VPNScanner) scanWireGuard() []scanner.Finding {
	matches, err := filepath.Glob(filepath.Join(s.wgConfDir, "*.conf"))
	if err != nil || len(matches) == 0 {
		return nil
	}

	var findings []scanner.Finding
	for _, path := range matches {
		findings = append(findings, parseWireGuardConfig(path)...)
	}
	return findings
}

// parseWireGuardConfig parses a single WireGuard config file for suspicious settings.
func parseWireGuardConfig(path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	configMtime := info.ModTime()

	var findings []scanner.Finding
	// Track state across sections.
	inPeer := false
	var currentPeerLines []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if strings.HasPrefix(line, "[Peer]") {
			// Flush previous peer if any.
			if inPeer && len(currentPeerLines) > 0 {
				ff := analyzePeer(path, currentPeerLines, configMtime)
				findings = append(findings, ff...)
			}
			inPeer = true
			currentPeerLines = nil
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// New section — flush peer.
			if inPeer && len(currentPeerLines) > 0 {
				ff := analyzePeer(path, currentPeerLines, configMtime)
				findings = append(findings, ff...)
			}
			inPeer = false
			currentPeerLines = nil
			continue
		}

		if inPeer {
			currentPeerLines = append(currentPeerLines, line)
		}
	}

	// Flush final peer.
	if inPeer && len(currentPeerLines) > 0 {
		ff := analyzePeer(path, currentPeerLines, configMtime)
		findings = append(findings, ff...)
	}

	return findings
}

// analyzePeer checks a WireGuard [Peer] block for suspicious configuration.
func analyzePeer(confPath string, lines []string, confMtime time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, line := range lines {
		if !strings.HasPrefix(strings.ToLower(line), "allowedips") {
			continue
		}
		// Check if AllowedIPs routes all traffic.
		value := extractValue(line)
		for _, cidr := range strings.Split(value, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "0.0.0.0/0" || cidr == "::/0" {
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID("vpn", confPath, "WireGuard AllowedIPs routes all traffic"),
					Scanner:  "vpn",
					Severity: scanner.SevLow,
					Title:    "WireGuard peer routes all traffic (AllowedIPs = 0.0.0.0/0)",
					Detail: fmt.Sprintf(
						"WireGuard config %q has a peer with AllowedIPs = %s, which routes all traffic through the VPN tunnel. This may expose internal routing or allow traffic interception by the peer.",
						confPath, cidr,
					),
					Evidence:    fmt.Sprintf("AllowedIPs: %s", cidr),
					Location:    confPath,
					Remediation: "Review whether routing all traffic through this peer is intentional. Consider using split-tunnel mode with specific IP ranges instead.",
				})
			}
		}
	}

	// Flag recently created/modified peer configs (mtime within 24h) as informational.
	if time.Since(confMtime) < 24*time.Hour {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("vpn", confPath, "recently modified WireGuard config"),
			Scanner:  "vpn",
			Severity: scanner.SevLow,
			Title:    "WireGuard configuration recently modified",
			Detail: fmt.Sprintf(
				"WireGuard configuration %q was modified within the last 24 hours (%s). A recently added peer could indicate an unauthorized VPN peer.",
				confPath, confMtime.Format(time.RFC3339),
			),
			Evidence:    fmt.Sprintf("mtime: %s", confMtime.Format(time.RFC3339)),
			Location:    confPath,
			Remediation: "Verify that all peers in this configuration are known and authorized.",
		})
	}

	return findings
}

// extractValue returns the value portion of a key = value line.
func extractValue(line string) string {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}

// ParseOpenVPNConfig parses an OpenVPN config file and returns findings.
// Exported for testing with synthetic input.
func ParseOpenVPNConfig(path string) []scanner.Finding {
	return parseOpenVPNConfig(path)
}

// scanOpenVPN scans all OpenVPN config files.
func (s *VPNScanner) scanOpenVPN() []scanner.Finding {
	// Try both .conf and .ovpn extensions.
	patterns := []string{
		filepath.Join(s.ovpnConfDir, "*.conf"),
		filepath.Join(s.ovpnConfDir, "*.ovpn"),
		filepath.Join(s.ovpnConfDir, "*/*.conf"),
		filepath.Join(s.ovpnConfDir, "*/*.ovpn"),
	}

	var findings []scanner.Finding
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			findings = append(findings, parseOpenVPNConfig(path)...)
		}
	}
	return findings
}

// parseOpenVPNConfig parses a single OpenVPN config file for suspicious settings.
func parseOpenVPNConfig(path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		lower := strings.ToLower(line)

		// Check for suspicious remote entries (non-standard ports or unknown IPs).
		if strings.HasPrefix(lower, "remote ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				host := fields[1]
				// Flag IP addresses (not hostnames) that look like private ranges
				// or loopback — these may indicate traffic redirection.
				if isPrivateOrLoopback(host) {
					location := fmt.Sprintf("%s:%d", path, lineNum)
					findings = append(findings, scanner.Finding{
						ID:       scanner.GenerateFindingID("vpn", location, "OpenVPN remote private IP"),
						Scanner:  "vpn",
						Severity: scanner.SevLow,
						Title:    "OpenVPN remote entry points to a private IP address",
						Detail: fmt.Sprintf(
							"OpenVPN config %q has a 'remote %s' directive pointing to a private/loopback IP address. This may indicate local traffic interception or a misconfigured configuration.",
							path, host,
						),
						Evidence:    line,
						Location:    location,
						Remediation: "Verify that the remote endpoint is the intended VPN server and not a rogue local host.",
					})
				}
			}
		}

		// Flag redirect-gateway which routes all traffic.
		if strings.Contains(lower, "redirect-gateway") {
			location := fmt.Sprintf("%s:%d", path, lineNum)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("vpn", location, "OpenVPN redirect-gateway"),
				Scanner:  "vpn",
				Severity: scanner.SevLow,
				Title:    "OpenVPN configuration routes all traffic through VPN",
				Detail: fmt.Sprintf(
					"OpenVPN config %q uses 'redirect-gateway', which routes all traffic through the VPN. This is informational but means all traffic is subject to VPN server inspection.",
					path,
				),
				Evidence:    line,
				Location:    location,
				Remediation: "Verify that routing all traffic through this VPN is intentional.",
			})
		}
	}
	return findings
}

// isPrivateOrLoopback returns true if the string looks like a private or
// loopback IP address.
func isPrivateOrLoopback(host string) bool {
	return strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.") ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == "localhost"
}
