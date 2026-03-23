package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// insecureServices is the set of legacy/insecure service names that should
// not be running on a hardened system.
var insecureServices = map[string]string{
	"telnetd":     "Telnet transmits all data (including passwords) in cleartext. Use SSH instead.",
	"rsh":         "RSH (remote shell) provides no encryption or strong authentication. Use SSH instead.",
	"rlogin":      "rlogin provides unauthenticated remote login. Replace with SSH.",
	"rexecd":      "rexecd executes commands remotely without encryption. Replace with SSH.",
	"xinetd":      "xinetd is a legacy super-server. Review whether any of its hosted services are necessary.",
	"rpcbind":     "rpcbind is required by NFS and other RPC services. Disable if NFS is not in use.",
	"avahi-daemon": "Avahi enables mDNS/DNS-SD service discovery, which can leak service information on the network. Disable if not required.",
}

// ServicesScanner enumerates running processes from /proc and flags legacy or
// insecure service daemons.
type ServicesScanner struct {
	procPath string
}

// NewServicesScanner creates a ServicesScanner with production defaults.
func NewServicesScanner() *ServicesScanner {
	return &ServicesScanner{procPath: "/proc"}
}

// NewServicesScannerWithPath creates a ServicesScanner with a custom /proc
// root (used in tests).
func NewServicesScannerWithPath(procPath string) *ServicesScanner {
	return &ServicesScanner{procPath: procPath}
}

func (s *ServicesScanner) Name() string            { return "services" }
func (s *ServicesScanner) Category() string        { return "system" }
func (s *ServicesScanner) RequiresRoot() bool      { return false }
func (s *ServicesScanner) RequiredTools() []string { return nil }
func (s *ServicesScanner) OptionalTools() []string { return nil }
func (s *ServicesScanner) Available() bool         { return true }
func (s *ServicesScanner) Description() string {
	return "Enumerates running processes via /proc and flags legacy or insecure service daemons such as telnetd, rsh, rlogin, and avahi-daemon."
}

// Scan reads /proc/*/comm files to enumerate running services and flags any
// known-insecure ones.
func (s *ServicesScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(s.procPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.procPath, err)
	}

	// Collect running service names from /proc/*/comm.
	seenNames := make(map[string]bool)
	totalProcs := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only numeric directories are process entries.
		pid := entry.Name()
		if !isNumeric(pid) {
			continue
		}
		totalProcs++

		commPath := filepath.Join(s.procPath, pid, "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if name != "" {
			seenNames[name] = true
		}
	}

	var findings []scanner.Finding

	// Flag any running service that matches the insecure list.
	for svcName, remediation := range insecureServices {
		if seenNames[svcName] {
			loc := s.procPath
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID(s.Name(), loc, "insecure service: "+svcName),
				Scanner:  s.Name(),
				Severity: scanner.SevHigh,
				Title:    fmt.Sprintf("Insecure or legacy service is running: %s", svcName),
				Detail: fmt.Sprintf(
					"The service %q was found running. This service is considered insecure or legacy and should not be active on a hardened system.",
					svcName,
				),
				Evidence:    fmt.Sprintf("running process: %s", svcName),
				Location:    loc,
				Remediation: remediation,
				References: []string{
					"https://www.cisecurity.org/benchmark/ubuntu_linux",
				},
				Metadata: map[string]string{
					"service_name": svcName,
				},
			})
		}
	}

	// Add an informational finding for total process count.
	_ = totalProcs // used for context; no finding needed unless explicitly asked

	return findings, nil
}

// isNumeric returns true if s consists entirely of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
