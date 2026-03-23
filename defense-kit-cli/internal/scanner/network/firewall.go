package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// FirewallScanner audits the host firewall configuration (iptables / nftables)
// for permissive rules or missing default-deny policies.
type FirewallScanner struct{}

// NewFirewallScanner creates a new FirewallScanner.
func NewFirewallScanner() *FirewallScanner {
	return &FirewallScanner{}
}

func (s *FirewallScanner) Name() string            { return "firewall" }
func (s *FirewallScanner) Category() string        { return "network" }
func (s *FirewallScanner) RequiresRoot() bool      { return true }
func (s *FirewallScanner) RequiredTools() []string { return nil }
func (s *FirewallScanner) OptionalTools() []string {
	return []string{"iptables", "nft", "ufw"}
}
func (s *FirewallScanner) Available() bool { return true }
func (s *FirewallScanner) Description() string {
	return "Audits host firewall configuration (iptables/nftables) for permissive rules or missing default-deny policies."
}

// Scan checks whether a firewall is active and flags dangerous configurations
// such as an open FORWARD chain or enabled IP forwarding.
func (s *FirewallScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, checkFirewallActive()...)
	findings = append(findings, checkIPForwarding()...)

	return findings, nil
}

// checkFirewallActive attempts to determine whether any firewall is in use and
// inspects the iptables FORWARD chain policy.
func checkFirewallActive() []scanner.Finding {
	// Try reading the saved iptables rules file first (no root needed for read).
	rulesFile := "/etc/iptables/rules.v4"
	rulesData, rulesErr := os.ReadFile(rulesFile)
	if rulesErr == nil {
		// Parse the static rules file.
		return parseIPTablesOutput(string(rulesData), rulesFile)
	}

	// Fall back to running iptables -L -n.
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		// iptables not installed — also check nft and ufw before flagging.
		if isNftablesActive() || isUFWActive() {
			return nil
		}
		return []scanner.Finding{{
			ID:          scanner.GenerateFindingID("firewall", "host", "No firewall detected"),
			Scanner:     "firewall",
			Severity:    scanner.SevMedium,
			Title:       "No firewall detected",
			Detail:      "Neither iptables, nftables, nor ufw appears to be installed or active on this host. Without a firewall, all inbound and outbound connections are permitted.",
			Evidence:    "iptables not found; nft not active; ufw not active",
			Location:    "host",
			Remediation: "Install and configure a firewall (e.g., ufw, iptables, or nftables) with a default-deny inbound policy.",
			References: []string{
				"https://www.cisecurity.org/insights/white-papers/cis-controls-v8",
			},
		}}
	}

	cmd := exec.Command(iptablesPath, "-L", "-n")
	out, err := cmd.Output()
	if err != nil {
		// Could not run iptables (permissions?); skip gracefully.
		return nil
	}

	return parseIPTablesOutput(string(out), "iptables -L -n")
}

// ParseIPTablesOutput scans iptables output for the FORWARD chain accepting all
// traffic. Exported for testing.
func ParseIPTablesOutput(output, source string) []scanner.Finding {
	return parseIPTablesOutput(output, source)
}

// parseIPTablesOutput scans iptables output for the FORWARD chain accepting all traffic.
func parseIPTablesOutput(output, source string) []scanner.Finding {
	var findings []scanner.Finding
	hasForwardAccept := false
	sc := bufio.NewScanner(strings.NewReader(output))

	inForwardChain := false
	for sc.Scan() {
		line := sc.Text()

		// Detect chain headers.
		if strings.HasPrefix(line, "Chain ") {
			inForwardChain = strings.Contains(line, "FORWARD")
			// Check for ACCEPT policy on FORWARD.
			if inForwardChain && strings.Contains(line, "policy ACCEPT") {
				hasForwardAccept = true
			}
			continue
		}

		// In rules.v4 format: :FORWARD ACCEPT [...]
		if strings.HasPrefix(line, ":FORWARD ACCEPT") {
			hasForwardAccept = true
		}
	}

	if hasForwardAccept {
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("firewall", source, "FORWARD chain policy is ACCEPT"),
			Scanner:     "firewall",
			Severity:    scanner.SevHigh,
			Title:       "Firewall FORWARD chain accepts all traffic",
			Detail:      "The iptables FORWARD chain has a default policy of ACCEPT, meaning this host can act as a packet router. This is dangerous unless intentional (e.g., a VPN gateway).",
			Evidence:    "FORWARD chain policy: ACCEPT",
			Location:    source,
			Remediation: "Set the FORWARD chain default policy to DROP: `iptables -P FORWARD DROP`. Allow only explicitly needed forwarded traffic.",
		})
	}

	return findings
}

// isNftablesActive returns true if nft is installed and shows active ruleset.
func isNftablesActive() bool {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return false
	}
	out, err := exec.Command(nft, "list", "ruleset").Output()
	if err != nil {
		return false
	}
	// A non-empty ruleset means nftables is active.
	return len(strings.TrimSpace(string(out))) > 0
}

// isUFWActive returns true if ufw is installed and reports as active.
func isUFWActive() bool {
	ufw, err := exec.LookPath("ufw")
	if err != nil {
		return false
	}
	out, err := exec.Command(ufw, "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "status: active")
}

// checkIPForwarding reads /proc/sys/net/ipv4/ip_forward and flags it HIGH if enabled.
func checkIPForwarding() []scanner.Finding {
	const path = "/proc/sys/net/ipv4/ip_forward"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	val := strings.TrimSpace(string(data))
	if val != "1" {
		return nil
	}

	return []scanner.Finding{{
		ID:          scanner.GenerateFindingID("firewall", path, "IP forwarding enabled"),
		Scanner:     "firewall",
		Severity:    scanner.SevHigh,
		Title:       "IP forwarding is enabled",
		Detail:      fmt.Sprintf("The sysctl net.ipv4.ip_forward is set to 1 (%s). This allows the host to route packets between interfaces, which may enable traffic interception if a firewall is misconfigured.", path),
		Evidence:    "net.ipv4.ip_forward=1",
		Location:    path,
		Remediation: "Disable IP forwarding unless this host is intentionally configured as a router or VPN gateway: `sysctl -w net.ipv4.ip_forward=0`. Persist the change in /etc/sysctl.conf.",
	}}
}
