package system

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// sysctlCheck describes a single sysctl parameter check.
type sysctlCheck struct {
	param    string         // dot-notation name (e.g. "net.ipv4.ip_forward")
	want     string         // expected secure value
	severity scanner.Severity
	title    string
	detail   string
	remediation string
}

// sysctlChecks is the list of kernel parameters audited by SysctlScanner.
var sysctlChecks = []sysctlCheck{
	{
		param:    "net.ipv4.ip_forward",
		want:     "0",
		severity: scanner.SevHigh,
		title:    "IP forwarding is enabled (net.ipv4.ip_forward = 1)",
		detail:   "IP forwarding allows this host to route packets between interfaces. Unless this machine is a router, enabling forwarding increases attack surface and may allow traffic to bypass firewall rules.",
		remediation: "Disable IP forwarding: set net.ipv4.ip_forward=0 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "kernel.randomize_va_space",
		want:     "2",
		severity: scanner.SevHigh,
		title:    "ASLR is not fully enabled (kernel.randomize_va_space != 2)",
		detail:   "Address Space Layout Randomization (ASLR) randomizes memory layout to make exploitation harder. A value of 2 enables full ASLR. Lower values reduce protection against memory-corruption attacks.",
		remediation: "Enable full ASLR: set kernel.randomize_va_space=2 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "kernel.sysrq",
		want:     "0",
		severity: scanner.SevMedium,
		title:    "SysRq key is enabled (kernel.sysrq != 0)",
		detail:   "The SysRq key allows users with physical or console access to invoke low-level kernel commands (reboot, memory dump, kill all processes). This should be disabled on production systems.",
		remediation: "Disable SysRq: set kernel.sysrq=0 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "kernel.dmesg_restrict",
		want:     "1",
		severity: scanner.SevMedium,
		title:    "dmesg is not restricted (kernel.dmesg_restrict != 1)",
		detail:   "When kernel.dmesg_restrict=0, unprivileged users can read kernel ring buffer messages via dmesg, which may reveal kernel addresses or other sensitive information useful for exploitation.",
		remediation: "Restrict dmesg: set kernel.dmesg_restrict=1 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "fs.suid_dumpable",
		want:     "0",
		severity: scanner.SevHigh,
		title:    "SUID process core dumps are allowed (fs.suid_dumpable != 0)",
		detail:   "When fs.suid_dumpable is non-zero, setuid processes can generate core dumps that may contain sensitive memory contents including credentials and cryptographic keys.",
		remediation: "Disable SUID core dumps: set fs.suid_dumpable=0 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "net.ipv4.conf.all.accept_redirects",
		want:     "0",
		severity: scanner.SevMedium,
		title:    "ICMP redirect acceptance is enabled (net.ipv4.conf.all.accept_redirects = 1)",
		detail:   "Accepting ICMP redirects allows routers to modify the routing table of this host, which can be abused for man-in-the-middle attacks.",
		remediation: "Disable ICMP redirects: set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "net.ipv4.conf.all.send_redirects",
		want:     "0",
		severity: scanner.SevMedium,
		title:    "ICMP redirect sending is enabled (net.ipv4.conf.all.send_redirects = 1)",
		detail:   "Sending ICMP redirects is only needed on routers. On non-router hosts, this capability can be abused to redirect traffic.",
		remediation: "Disable sending ICMP redirects: set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
	{
		param:    "net.ipv4.tcp_syncookies",
		want:     "1",
		severity: scanner.SevMedium,
		title:    "TCP SYN cookies are disabled (net.ipv4.tcp_syncookies = 0)",
		detail:   "TCP SYN cookies protect against SYN flood denial-of-service attacks. They should be enabled on all public-facing hosts.",
		remediation: "Enable SYN cookies: set net.ipv4.tcp_syncookies=1 in /etc/sysctl.conf and run 'sysctl -p'.",
	},
}

// SysctlScanner reads kernel sysctl parameters from /proc/sys and flags
// insecure values.
type SysctlScanner struct {
	procSysPath string
}

// NewSysctlScanner creates a SysctlScanner with production defaults.
func NewSysctlScanner() *SysctlScanner {
	return &SysctlScanner{procSysPath: "/proc/sys"}
}

// NewSysctlScannerWithPath creates a SysctlScanner with a custom /proc/sys
// root (used in tests).
func NewSysctlScannerWithPath(procSysPath string) *SysctlScanner {
	return &SysctlScanner{procSysPath: procSysPath}
}

func (s *SysctlScanner) Name() string            { return "sysctl" }
func (s *SysctlScanner) Category() string        { return "system" }
func (s *SysctlScanner) RequiresRoot() bool      { return false }
func (s *SysctlScanner) RequiredTools() []string { return nil }
func (s *SysctlScanner) OptionalTools() []string { return nil }
func (s *SysctlScanner) Available() bool         { return true }
func (s *SysctlScanner) Description() string {
	return "Reads kernel sysctl parameters from /proc/sys and flags insecure values such as enabled IP forwarding, disabled ASLR, and permissive core dump settings."
}

// Scan checks each configured sysctl parameter and returns a finding for
// every parameter whose value differs from the expected secure value.
func (s *SysctlScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	for _, check := range sysctlChecks {
		f, err := s.checkParam(check)
		if err != nil {
			// Parameter not readable — skip silently.
			continue
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkParam reads a single sysctl parameter and returns a Finding if its
// value does not match the expected secure value, or nil if it is secure.
func (s *SysctlScanner) checkParam(check sysctlCheck) (*scanner.Finding, error) {
	path := s.paramToPath(check.param)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(data))

	if value == check.want {
		return nil, nil
	}

	f := scanner.Finding{
		ID:          scanner.GenerateFindingID(s.Name(), path, check.title),
		Scanner:     s.Name(),
		Severity:    check.severity,
		Title:       check.title,
		Detail:      check.detail,
		Evidence:    fmt.Sprintf("%s = %s (want %s)", check.param, value, check.want),
		Location:    path,
		Remediation: check.remediation,
		CanAutoFix:  true,
		Metadata: map[string]string{
			"sysctl_param":   check.param,
			"current_value":  value,
			"expected_value": check.want,
		},
	}
	return &f, nil
}

// paramToPath converts a dot-notation sysctl name to its /proc/sys path.
// For example, "net.ipv4.ip_forward" → "/proc/sys/net/ipv4/ip_forward".
func (s *SysctlScanner) paramToPath(param string) string {
	rel := strings.ReplaceAll(param, ".", "/")
	return s.procSysPath + "/" + rel
}
