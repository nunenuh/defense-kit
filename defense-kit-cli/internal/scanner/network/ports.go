package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// commonPorts is the set of listening ports that are considered normal on a
// typical Linux system. Ports not in this set generate MEDIUM findings.
var commonPorts = map[uint16]bool{
	22:   true, // SSH
	53:   true, // DNS
	80:   true, // HTTP
	443:  true, // HTTPS
	631:  true, // CUPS printing
	5353: true, // mDNS
	8080: true, // HTTP alternate
}

// procFiles lists the /proc/net files that describe TCP listening sockets.
var procFiles = []string{
	"/proc/net/tcp",
	"/proc/net/tcp6",
}

// tcpListenState is the hex state code for a listening socket in /proc/net/tcp.
const tcpListenState = "0A"

// PortsScanner parses /proc/net/tcp and /proc/net/tcp6 to find unusual
// listening ports.
type PortsScanner struct{}

// NewPortsScanner creates a new PortsScanner.
func NewPortsScanner() *PortsScanner {
	return &PortsScanner{}
}

func (s *PortsScanner) Name() string           { return "ports" }
func (s *PortsScanner) Category() string       { return "network" }
func (s *PortsScanner) RequiresRoot() bool     { return false }
func (s *PortsScanner) RequiredTools() []string { return nil }
func (s *PortsScanner) OptionalTools() []string { return nil }
func (s *PortsScanner) Available() bool        { return true }
func (s *PortsScanner) Description() string {
	return "Parses /proc/net/tcp and /proc/net/tcp6 to find TCP ports in LISTEN state that are not in the expected common-ports set."
}

// Scan reads the kernel TCP tables and flags any listening port that is not in
// the known-common set.
func (s *PortsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	seen := make(map[uint16]bool)
	var findings []scanner.Finding

	for _, procFile := range procFiles {
		ports, err := parseProcNetTCP(procFile)
		if err != nil {
			// /proc/net/tcp6 may not exist on all kernels; skip gracefully.
			continue
		}
		for _, port := range ports {
			if seen[port] {
				continue
			}
			seen[port] = true

			if commonPorts[port] {
				continue
			}

			loc := fmt.Sprintf("tcp:%d", port)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("ports", loc, "Unusual listening port"),
				Scanner:     "ports",
				Severity:    scanner.SevMedium,
				Title:       "Unusual listening port",
				Detail:      fmt.Sprintf("Port %d is in LISTEN state but is not in the expected common-ports set. Verify that this service is intentional.", port),
				Evidence:    fmt.Sprintf("port=%d", port),
				Location:    loc,
				Remediation: fmt.Sprintf("Identify the process listening on port %d (use 'ss -tlnp' or 'lsof -i :%d'). If the service is not required, stop it and disable it at boot.", port, port),
				References: []string{
					"https://www.cisecurity.org/insights/white-papers/cis-controls-v8",
				},
			})
		}
	}

	return findings, nil
}

// ParseProcNetTCPFile reads a /proc/net/tcp or /proc/net/tcp6 file and returns
// the decimal port numbers of all sockets in LISTEN state. It is exported to
// allow direct testing with synthetic files.
func ParseProcNetTCPFile(path string) ([]uint16, error) {
	return parseProcNetTCP(path)
}

// parseProcNetTCP reads a /proc/net/tcp or /proc/net/tcp6 file and returns
// the decimal port numbers of all sockets in LISTEN state.
func parseProcNetTCP(path string) ([]uint16, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ports []uint16
	sc := bufio.NewScanner(f)

	// Skip the header line.
	sc.Scan()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		port, ok := extractListeningPort(line)
		if !ok {
			continue
		}
		ports = append(ports, port)
	}

	return ports, sc.Err()
}

// extractListeningPort parses a single data line from /proc/net/tcp[6] and
// returns the local port number if the socket is in LISTEN state (0A).
//
// /proc/net/tcp line format (space-separated, zero-indexed fields):
//
//	sl  local_address rem_address   st tx_queue:rx_queue ...
//	 0  0100007F:0035 00000000:0000 0A ...
//
// local_address encodes <hex_ip>:<hex_port> in big-endian byte order.
func extractListeningPort(line string) (uint16, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return 0, false
	}

	// Field 3 (index 3) is the st (state) column.
	state := strings.ToUpper(strings.TrimSpace(fields[3]))
	if state != tcpListenState {
		return 0, false
	}

	// Field 1 (index 1) is local_address: "HHHHHHHH:HHHH" or
	// "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH:HHHH" for IPv6.
	localAddr := fields[1]
	colonIdx := strings.LastIndex(localAddr, ":")
	if colonIdx < 0 {
		return 0, false
	}

	hexPort := localAddr[colonIdx+1:]
	portBytes, err := hex.DecodeString(hexPort)
	if err != nil || len(portBytes) != 2 {
		// Fall back to simple integer parse.
		v, err2 := strconv.ParseUint(hexPort, 16, 16)
		if err2 != nil {
			return 0, false
		}
		return uint16(v), true
	}

	// /proc/net/tcp stores the port in big-endian (network byte order).
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return port, true
}
