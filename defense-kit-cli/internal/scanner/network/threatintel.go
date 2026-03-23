package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// knownBadRanges contains CIDR ranges associated with malicious activity.
// These are documentation/placeholder ranges — expand with real threat intel feeds.
var knownBadRanges = []string{
	// TEST-NET ranges (RFC 5737) — placeholders for real threat intel
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3

	// Known C2 infrastructure ranges (examples — replace with live feeds)
	"185.220.101.0/24", // Tor exit node range (example)
	"185.220.102.0/24", // Tor exit node range (example)
	"185.220.103.0/24", // Tor exit node range (example)
	"199.87.154.0/24",  // Known malware C2 range (placeholder)
	"198.98.51.0/24",   // Known C2 infrastructure (placeholder)
	"192.42.116.0/24",  // Tor exit range (placeholder)
	"192.42.117.0/24",  // Tor exit range (placeholder)
	"192.42.118.0/24",  // Tor exit range (placeholder)

	// Common malware callback ranges (placeholders)
	"46.161.27.0/24",   // Malware C2 (placeholder)
	"46.161.28.0/24",   // Malware C2 (placeholder)
	"91.108.4.0/22",    // Known bad ASN range (placeholder)
	"91.108.56.0/22",   // Known bad ASN range (placeholder)
	"149.154.160.0/20", // Known bad range (placeholder)

	// Bulletproof hosting ranges (placeholders)
	"5.45.86.0/24",   // Bulletproof hosting (placeholder)
	"5.45.87.0/24",   // Bulletproof hosting (placeholder)
	"31.184.236.0/24", // Known malicious hosting (placeholder)
	"31.184.237.0/24", // Known malicious hosting (placeholder)
	"31.184.238.0/24", // Known malicious hosting (placeholder)

	// Additional C2 ranges (placeholders for real intel)
	"77.73.133.0/24",  // C2 infrastructure (placeholder)
	"77.73.134.0/24",  // C2 infrastructure (placeholder)
	"95.142.46.0/24",  // Known bad range (placeholder)
	"95.142.47.0/24",  // Known bad range (placeholder)
	"104.244.72.0/21", // Known malicious range (placeholder)
	"104.244.76.0/22", // Known malicious range (placeholder)
	"107.189.10.0/24", // Tor exit nodes (placeholder)
	"107.189.11.0/24", // Tor exit nodes (placeholder)
	"107.189.12.0/24", // Tor exit nodes (placeholder)

	// Botnet C2 infrastructure (placeholders)
	"185.130.44.0/24", // Botnet C2 (placeholder)
	"185.130.45.0/24", // Botnet C2 (placeholder)
	"185.130.46.0/24", // Botnet C2 (placeholder)
	"185.56.80.0/22",  // Malicious infrastructure (placeholder)
	"185.56.84.0/22",  // Malicious infrastructure (placeholder)

	// Additional Tor exit node ranges (placeholders)
	"176.10.99.0/24",  // Tor exit (placeholder)
	"176.10.107.0/24", // Tor exit (placeholder)
	"193.238.46.0/24", // Tor exit (placeholder)
	"193.238.47.0/24", // Tor exit (placeholder)

	// Known malware delivery infrastructure (placeholders)
	"5.188.86.0/24",  // Malware delivery (placeholder)
	"5.188.87.0/24",  // Malware delivery (placeholder)
	"5.188.88.0/24",  // Malware delivery (placeholder)
	"5.188.89.0/24",  // Malware delivery (placeholder)
	"45.142.212.0/24", // Known bad (placeholder)
	"45.142.213.0/24", // Known bad (placeholder)
}

// knownBadDomains contains domain names associated with malicious activity.
// These are placeholders — expand with real threat intel feeds (e.g., domain blocklists).
var knownBadDomains = []string{
	// Placeholder malicious domains (replace with real threat intel)
	"evil.com",
	"malware.com",
	"c2server.com",
	"botnet-cc.net",
	"malicious-cdn.org",
	"phishing-kit.net",
	"ransomware-c2.com",
	"exfil-target.net",
	"keylogger-host.com",
	"rat-controller.net",
	"stealer-c2.com",
	"ddos-bot.net",
	"cryptominer-pool.com",
	"spyware-server.org",
	"adware-tracker.net",
}

// threatTypeForRange maps CIDR prefixes to a threat type label.
var threatTypeForRange = map[string]string{
	"185.220.101.": "tor",
	"185.220.102.": "tor",
	"185.220.103.": "tor",
	"192.42.116.":  "tor",
	"192.42.117.":  "tor",
	"192.42.118.":  "tor",
	"176.10.99.":   "tor",
	"176.10.107.":  "tor",
	"193.238.46.":  "tor",
	"193.238.47.":  "tor",
	"107.189.10.":  "tor",
	"107.189.11.":  "tor",
	"107.189.12.":  "tor",
}

// parsedBadRange holds a compiled CIDR network for fast matching.
type parsedBadRange struct {
	network   *net.IPNet
	cidr      string
	threatType string
}

// ThreatIntelScanner checks active network connections against known-bad
// IP ranges and domains.
type ThreatIntelScanner struct {
	// procNetFiles allows overriding /proc/net/tcp* paths in tests.
	procNetFiles []string
	// resolvConfPath allows overriding /etc/resolv.conf in tests.
	resolvConfPath string
	// badRanges holds the compiled threat intel IP ranges.
	badRanges []parsedBadRange
	// badDomainSet is a set of known-bad domain names (lowercased).
	badDomainSet map[string]bool
}

// NewThreatIntelScanner creates a ThreatIntelScanner with the default embedded
// threat intel lists.
func NewThreatIntelScanner() *ThreatIntelScanner {
	s := &ThreatIntelScanner{
		procNetFiles:   []string{"/proc/net/tcp", "/proc/net/tcp6"},
		resolvConfPath: "/etc/resolv.conf",
		badDomainSet:   make(map[string]bool),
	}
	s.compileBadRanges(knownBadRanges)
	for _, d := range knownBadDomains {
		s.badDomainSet[strings.ToLower(d)] = true
	}
	return s
}

// compileBadRanges parses and stores CIDR strings, skipping any that fail.
func (s *ThreatIntelScanner) compileBadRanges(cidrs []string) {
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		tt := inferThreatType(cidr)
		s.badRanges = append(s.badRanges, parsedBadRange{
			network:    network,
			cidr:       cidr,
			threatType: tt,
		})
	}
}

// inferThreatType returns a threat type label for a given CIDR string.
func inferThreatType(cidr string) string {
	// Check prefix-based mapping first.
	for prefix, tt := range threatTypeForRange {
		if strings.HasPrefix(cidr, prefix) {
			return tt
		}
	}
	// Heuristic: if the range description mentions "tor" or starts with certain prefixes.
	if strings.Contains(strings.ToLower(cidr), "tor") {
		return "tor"
	}
	return "c2"
}

// matchIP returns (cidr, threatType, true) if the IP is in a known-bad range.
func (s *ThreatIntelScanner) matchIP(ipStr string) (string, string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", false
	}
	for _, r := range s.badRanges {
		if r.network.Contains(ip) {
			return r.cidr, r.threatType, true
		}
	}
	return "", "", false
}

func (s *ThreatIntelScanner) Name() string           { return "threat_intel" }
func (s *ThreatIntelScanner) Category() string       { return "network" }
func (s *ThreatIntelScanner) RequiresRoot() bool     { return false }
func (s *ThreatIntelScanner) RequiredTools() []string { return nil }
func (s *ThreatIntelScanner) OptionalTools() []string { return nil }
func (s *ThreatIntelScanner) Available() bool        { return true }
func (s *ThreatIntelScanner) Description() string {
	return "Checks active network connections against embedded known-bad IP ranges and domains (C2, Tor, malware)."
}

// Scan reads active TCP connections and /etc/resolv.conf, flagging any that
// match the embedded threat intel lists.
func (s *ThreatIntelScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// --- Check active TCP connections ---
	for _, path := range s.procNetFiles {
		conns, err := parseProcNetTCPConns(path)
		if err != nil {
			continue
		}
		for _, c := range conns {
			cidr, threatType, matched := s.matchIP(c.remoteIP)
			if !matched {
				continue
			}
			title := fmt.Sprintf("Connection to known malicious IP: %s", c.remoteIP)
			evidence := fmt.Sprintf("%s:%d → %s:%d (matched %s)", c.localIP, c.localPort, c.remoteIP, c.remotePort, cidr)
			loc := fmt.Sprintf("/proc/net/tcp → %s:%d", c.remoteIP, c.remotePort)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("threat_intel", loc, title),
				Scanner:  "threat_intel",
				Severity: scanner.SevCritical,
				Title:    title,
				Detail:   fmt.Sprintf("An active ESTABLISHED TCP connection was detected to %s (port %d), which falls within the known-bad range %s. Threat type: %s.", c.remoteIP, c.remotePort, cidr, threatType),
				Evidence: evidence,
				Location: loc,
				Remediation: "Immediately investigate the source process of this connection. Block the IP at the firewall, kill the offending process, and audit the system for compromise.",
				References: []string{
					"https://attack.mitre.org/techniques/T1071/",
					"https://attack.mitre.org/techniques/T1090/003/",
				},
				Metadata: map[string]string{
					"remote_ip":    c.remoteIP,
					"remote_port":  fmt.Sprintf("%d", c.remotePort),
					"matched_list": cidr,
					"threat_type":  threatType,
				},
			})
		}
	}

	// --- Check /etc/resolv.conf nameservers ---
	dnsFindings := s.checkResolvConf(s.resolvConfPath)
	findings = append(findings, dnsFindings...)

	return findings, nil
}

// checkResolvConf reads the resolv.conf file and checks nameservers against
// known-bad domain and IP lists.
func (s *ThreatIntelScanner) checkResolvConf(path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ns := fields[1]

		// Check if the nameserver IP is in a known-bad range.
		if cidr, threatType, matched := s.matchIP(ns); matched {
			title := fmt.Sprintf("Nameserver %s is in known-bad IP range", ns)
			evidence := fmt.Sprintf("nameserver %s matched %s", ns, cidr)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("threat_intel", path, title),
				Scanner:  "threat_intel",
				Severity: scanner.SevCritical,
				Title:    title,
				Detail:   fmt.Sprintf("The configured DNS nameserver %s falls within the known-bad range %s (threat type: %s). This may indicate DNS hijacking or use of a malicious resolver.", ns, cidr, threatType),
				Evidence: evidence,
				Location: path,
				Remediation: "Replace the nameserver with a trusted DNS provider (e.g., 8.8.8.8, 1.1.1.1). Investigate how this nameserver was configured.",
				References: []string{
					"https://attack.mitre.org/techniques/T1071/004/",
					"https://attack.mitre.org/techniques/T1590/002/",
				},
				Metadata: map[string]string{
					"nameserver":   ns,
					"matched_list": cidr,
					"threat_type":  threatType,
				},
			})
		}

		// Check if the nameserver matches a known-bad domain.
		if s.badDomainSet[strings.ToLower(ns)] {
			title := fmt.Sprintf("Nameserver %s is a known malicious domain", ns)
			evidence := fmt.Sprintf("nameserver %s found in malicious domain list", ns)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("threat_intel", path+ns, title),
				Scanner:  "threat_intel",
				Severity: scanner.SevCritical,
				Title:    title,
				Detail:   fmt.Sprintf("The configured DNS nameserver %q is listed as a known malicious domain. All DNS queries may be intercepted or manipulated.", ns),
				Evidence: evidence,
				Location: path,
				Remediation: "Replace the nameserver immediately. Investigate how this was configured and audit recent DNS activity.",
				References: []string{
					"https://attack.mitre.org/techniques/T1071/004/",
				},
				Metadata: map[string]string{
					"nameserver":   ns,
					"matched_list": "known_bad_domains",
					"threat_type":  "malware",
				},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Exported helpers for testing
// ---------------------------------------------------------------------------

// ThreatIntelScannerWithOverrides creates a ThreatIntelScanner with
// injectable paths and custom threat lists for use in tests.
func ThreatIntelScannerWithOverrides(procFiles []string, resolvConf string, cidrs []string, domains []string) *ThreatIntelScanner {
	s := &ThreatIntelScanner{
		procNetFiles:   procFiles,
		resolvConfPath: resolvConf,
		badDomainSet:   make(map[string]bool),
	}
	s.compileBadRanges(cidrs)
	for _, d := range domains {
		s.badDomainSet[strings.ToLower(d)] = true
	}
	return s
}
