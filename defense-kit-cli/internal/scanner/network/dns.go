package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// knownGoodResolvers is the set of widely trusted public DNS servers.
var knownGoodResolvers = map[string]bool{
	"8.8.8.8":         true, // Google
	"8.8.4.4":         true, // Google
	"1.1.1.1":         true, // Cloudflare
	"1.0.0.1":         true, // Cloudflare
	"9.9.9.9":         true, // Quad9
	"208.67.222.222":  true, // OpenDNS
	"208.67.220.220":  true, // OpenDNS
}

// DNSScanner checks DNS resolver configuration for signs of hijacking or
// misconfiguration (e.g., unexpected resolvers in /etc/resolv.conf).
type DNSScanner struct{}

// NewDNSScanner creates a new DNSScanner.
func NewDNSScanner() *DNSScanner {
	return &DNSScanner{}
}

func (s *DNSScanner) Name() string            { return "dns" }
func (s *DNSScanner) Category() string        { return "network" }
func (s *DNSScanner) RequiresRoot() bool      { return false }
func (s *DNSScanner) RequiredTools() []string { return nil }
func (s *DNSScanner) OptionalTools() []string { return nil }
func (s *DNSScanner) Available() bool         { return true }
func (s *DNSScanner) Description() string {
	return "Checks DNS resolver configuration for signs of hijacking or misconfiguration, including unexpected entries in /etc/resolv.conf and /etc/hosts."
}

// Scan inspects /etc/resolv.conf (and optionally /etc/systemd/resolved.conf)
// for rogue or misconfigured nameserver entries.
func (s *DNSScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, parseResolvConf("/etc/resolv.conf")...)
	findings = append(findings, parseSystemdResolved("/etc/systemd/resolved.conf")...)

	return findings, nil
}

// ParseResolvConf reads a resolv.conf-style file and flags unknown or multiple
// differing nameservers. Exported for testing.
func ParseResolvConf(path string) []scanner.Finding {
	return parseResolvConf(path)
}

// parseResolvConf reads a resolv.conf-style file and flags unknown or multiple
// differing nameservers.
func parseResolvConf(path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		// File absent — nothing to flag.
		return nil
	}
	defer f.Close()

	var nameservers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			nameservers = append(nameservers, fields[1])
		}
	}

	if len(nameservers) == 0 {
		return nil
	}

	var findings []scanner.Finding

	// Check each nameserver.
	rogueCount := 0
	for _, ns := range nameservers {
		if !knownGoodResolvers[ns] {
			rogueCount++
			loc := fmt.Sprintf("%s: nameserver %s", path, ns)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("dns", loc, "Unknown DNS resolver"),
				Scanner:     "dns",
				Severity:    scanner.SevHigh,
				Title:       "Unknown DNS resolver",
				Detail:      fmt.Sprintf("Nameserver %q is not in the list of well-known public resolvers. It may indicate DNS hijacking or an unintentional configuration.", ns),
				Evidence:    fmt.Sprintf("nameserver %s", ns),
				Location:    path,
				Remediation: "Verify that this nameserver is intentional. If using a local resolver (127.0.0.1 or ::1), ensure it is properly secured. Otherwise, consider using a well-known public resolver.",
				References: []string{
					"https://www.cisecurity.org/insights/white-papers/cis-controls-v8",
				},
			})
		}
	}

	// Flag multiple differing nameservers (could be split-horizon or misconfiguration).
	if len(nameservers) > 1 {
		// Only flag if they are not all the same.
		unique := make(map[string]struct{})
		for _, ns := range nameservers {
			unique[ns] = struct{}{}
		}
		if len(unique) > 1 {
			evidence := strings.Join(nameservers, ", ")
			loc := fmt.Sprintf("%s: multiple nameservers", path)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("dns", loc, "Multiple differing nameservers configured"),
				Scanner:     "dns",
				Severity:    scanner.SevMedium,
				Title:       "Multiple differing nameservers configured",
				Detail:      fmt.Sprintf("Multiple distinct nameservers are configured (%s). This can cause inconsistent DNS resolution and may indicate tampering.", evidence),
				Evidence:    evidence,
				Location:    path,
				Remediation: "Review /etc/resolv.conf and ensure only trusted nameservers are listed. Remove any unexpected entries.",
			})
		}
	}

	return findings
}

// ParseSystemdResolved checks a systemd-resolved config file for DNS-over-HTTPS
// endpoints that point to unknown servers. Exported for testing.
func ParseSystemdResolved(path string) []scanner.Finding {
	return parseSystemdResolved(path)
}

// parseSystemdResolved checks /etc/systemd/resolved.conf for DNS-over-HTTPS
// endpoints that point to unknown servers.
func parseSystemdResolved(path string) []scanner.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Look for DNSOverHTTPS= setting with a value.
		if strings.HasPrefix(strings.ToUpper(line), "DNSOVERHTTPS=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				// Any non-empty, non-"no" value points to an endpoint.
				if val != "" && !strings.EqualFold(val, "no") && !strings.EqualFold(val, "false") && !strings.EqualFold(val, "0") {
					loc := fmt.Sprintf("%s: DNSOverHTTPS", path)
					findings = append(findings, scanner.Finding{
						ID:          scanner.GenerateFindingID("dns", loc, "DNS-over-HTTPS configured"),
						Scanner:     "dns",
						Severity:    scanner.SevMedium,
						Title:       "DNS-over-HTTPS configured",
						Detail:      fmt.Sprintf("DNS-over-HTTPS is enabled in systemd-resolved (%s). Verify the endpoint is a trusted provider.", val),
						Evidence:    line,
						Location:    path,
						Remediation: "Confirm that the DNS-over-HTTPS endpoint is a known, trusted provider. Disable if not required.",
					})
				}
			}
		}
	}

	return findings
}
