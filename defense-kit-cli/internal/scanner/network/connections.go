package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// tcpEstablishedState is the hex state code for an established TCP connection.
const tcpEstablishedState = "01"

// standardRemotePorts are common, expected remote ports for outbound connections.
var standardRemotePorts = map[uint16]bool{
	22:   true, // SSH
	25:   true, // SMTP
	53:   true, // DNS
	80:   true, // HTTP
	443:  true, // HTTPS
	587:  true, // SMTP submission
	993:  true, // IMAPS
	995:  true, // POP3S
	8080: true, // HTTP alternate
	8443: true, // HTTPS alternate
}

// reverseSellPorts are well-known attacker / reverse-shell ports.
var reverseShellPorts = map[uint16]bool{
	4444:  true,
	4445:  true,
	5555:  true,
	6666:  true,
	1337:  true,
	31337: true,
}

// ircPorts are IRC ports commonly used as C2 channels.
var ircPorts = map[uint16]bool{
	6667: true,
	6668: true,
	6669: true,
}

// torPorts are Tor SOCKS proxy ports.
var torPorts = map[uint16]bool{
	9050: true,
	9150: true,
}

// suspiciousSystemProcs are system daemons that should not be making outbound
// connections under normal circumstances.
var suspiciousSystemProcs = map[string]bool{
	"sshd":    true,
	"systemd": true,
	"cron":    true,
}

// connEntry holds a parsed row from /proc/net/tcp[6].
type connEntry struct {
	localIP    string
	localPort  uint16
	remoteIP   string
	remotePort uint16
	inode      string
}

// ConnectionsScanner inspects active network connections for suspicious
// outbound or lateral-movement traffic patterns.
type ConnectionsScanner struct {
	// procNetFiles allows overriding the /proc/net/tcp* paths in tests.
	procNetFiles []string
	// procRoot allows overriding /proc in tests.
	procRoot string
}

// NewConnectionsScanner creates a new ConnectionsScanner.
func NewConnectionsScanner() *ConnectionsScanner {
	return &ConnectionsScanner{
		procNetFiles: []string{"/proc/net/tcp", "/proc/net/tcp6"},
		procRoot:     "/proc",
	}
}

func (s *ConnectionsScanner) Name() string           { return "connections" }
func (s *ConnectionsScanner) Category() string       { return "network" }
func (s *ConnectionsScanner) RequiresRoot() bool     { return false }
func (s *ConnectionsScanner) RequiredTools() []string { return nil }
func (s *ConnectionsScanner) OptionalTools() []string { return nil }
func (s *ConnectionsScanner) Available() bool        { return true }
func (s *ConnectionsScanner) Description() string {
	return "Inspects active network connections for suspicious outbound or lateral-movement traffic patterns."
}

// Scan reads /proc/net/tcp[6] and /proc/*/fd/ to detect suspicious ESTABLISHED
// connections.
func (s *ConnectionsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// 1. Parse all ESTABLISHED connections.
	conns := s.parseEstablished()
	if len(conns) == 0 {
		return nil, nil
	}

	// 2. Build inode → (pid, name) map.
	inodeMap := s.buildInodeMap()

	// 3. Analyse each connection.
	var findings []scanner.Finding

	// Track connection count per PID for beaconing/scanning detection.
	pidConns := make(map[int]int)

	type pidConn struct {
		pid  int
		name string
		conn connEntry
	}
	var resolved []pidConn

	for _, c := range conns {
		pid, name := 0, "unknown"
		if info, ok := inodeMap[c.inode]; ok {
			pid = info.pid
			name = info.name
		}
		if pid > 0 {
			pidConns[pid]++
		}
		resolved = append(resolved, pidConn{pid, name, c})
	}

	for _, rc := range resolved {
		c := rc.conn
		pid := rc.pid
		name := rc.name
		loc := fmt.Sprintf("PID:%d (%s)", pid, name)
		evidence := fmt.Sprintf("%s:%d → %s:%d", c.localIP, c.localPort, c.remoteIP, c.remotePort)

		meta := map[string]string{
			"pid":          strconv.Itoa(pid),
			"process_name": name,
			"remote_ip":    c.remoteIP,
			"remote_port":  strconv.Itoa(int(c.remotePort)),
		}

		// Check: reverse shell / common attacker ports (CRITICAL).
		if reverseShellPorts[c.remotePort] {
			title := fmt.Sprintf("Outbound connection to suspicious port %d", c.remotePort)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
				Scanner:  "connections",
				Severity: scanner.SevCritical,
				Title:    title,
				Detail:   fmt.Sprintf("Process %q (PID %d) has an ESTABLISHED connection to %s on port %d, a well-known reverse-shell/RAT port.", name, pid, c.remoteIP, c.remotePort),
				Evidence: evidence,
				Location: loc,
				Remediation: "Immediately investigate this connection. Kill the process if it is unexpected and audit how it was started.",
				References:  []string{"https://attack.mitre.org/techniques/T1571/"},
				Metadata:    meta,
			})
			continue
		}

		// Check: IRC / C2 channel ports (HIGH).
		if ircPorts[c.remotePort] {
			title := fmt.Sprintf("Outbound connection to IRC/C2 port %d", c.remotePort)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
				Scanner:  "connections",
				Severity: scanner.SevHigh,
				Title:    title,
				Detail:   fmt.Sprintf("Process %q (PID %d) has an ESTABLISHED connection to %s on port %d, which is an IRC port often used as a C2 channel.", name, pid, c.remoteIP, c.remotePort),
				Evidence: evidence,
				Location: loc,
				Remediation: "Investigate the process and connection. Block outbound IRC traffic via firewall if it is not required.",
				References:  []string{"https://attack.mitre.org/techniques/T1219/"},
				Metadata:    meta,
			})
			continue
		}

		// Check: Tor SOCKS ports (HIGH).
		if torPorts[c.remotePort] {
			title := fmt.Sprintf("Outbound connection to Tor port %d", c.remotePort)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
				Scanner:  "connections",
				Severity: scanner.SevHigh,
				Title:    title,
				Detail:   fmt.Sprintf("Process %q (PID %d) has an ESTABLISHED connection to %s on port %d, which may indicate Tor usage for data exfiltration or C2 anonymisation.", name, pid, c.remoteIP, c.remotePort),
				Evidence: evidence,
				Location: loc,
				Remediation: "Investigate whether Tor is intentionally installed. Block port 9050/9150 at the firewall if Tor is not required.",
				References:  []string{"https://attack.mitre.org/techniques/T1090/003/"},
				Metadata:    meta,
			})
			continue
		}

		// Check: suspicious system process with outbound connection (HIGH).
		if suspiciousSystemProcs[name] {
			title := fmt.Sprintf("System process %q has unexpected outbound connection", name)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
				Scanner:  "connections",
				Severity: scanner.SevHigh,
				Title:    title,
				Detail:   fmt.Sprintf("System daemon %q (PID %d) has an ESTABLISHED outbound connection to %s:%d. This is unusual and may indicate compromise.", name, pid, c.remoteIP, c.remotePort),
				Evidence: evidence,
				Location: loc,
				Remediation: "Inspect the process and its parent. Review system logs for unexpected activity around this daemon.",
				References:  []string{"https://attack.mitre.org/techniques/T1543/"},
				Metadata:    meta,
			})
			continue
		}

		// Check: process running from /tmp or /dev/shm (CRITICAL).
		if pid > 0 {
			exePath := readProcessExe(pid)
			if strings.HasPrefix(exePath, "/tmp/") || strings.HasPrefix(exePath, "/dev/shm/") {
				title := fmt.Sprintf("Connection from process in suspicious location: %s", exePath)
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
					Scanner:  "connections",
					Severity: scanner.SevCritical,
					Title:    title,
					Detail:   fmt.Sprintf("Process %q (PID %d) executed from %q has an ESTABLISHED connection to %s:%d. Executables in /tmp or /dev/shm are a strong malware indicator.", name, pid, exePath, c.remoteIP, c.remotePort),
					Evidence: evidence,
					Location: loc,
					Remediation: "Kill the process immediately. Investigate how it was placed in /tmp or /dev/shm and look for persistence mechanisms.",
					References:  []string{"https://attack.mitre.org/techniques/T1036/"},
					Metadata: map[string]string{
						"pid":          strconv.Itoa(pid),
						"process_name": name,
						"remote_ip":    c.remoteIP,
						"remote_port":  strconv.Itoa(int(c.remotePort)),
						"exe_path":     exePath,
					},
				})
				continue
			}
		}

		// Check: non-standard remote port (MEDIUM).
		if !standardRemotePorts[c.remotePort] {
			title := fmt.Sprintf("Outbound connection to non-standard port %d", c.remotePort)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc+evidence, title),
				Scanner:  "connections",
				Severity: scanner.SevMedium,
				Title:    title,
				Detail:   fmt.Sprintf("Process %q (PID %d) has an ESTABLISHED connection to %s on port %d, which is not in the expected set of standard remote ports.", name, pid, c.remoteIP, c.remotePort),
				Evidence: evidence,
				Location: loc,
				Remediation: "Verify that this connection is intentional. If the service is not required, terminate it and block the port at the firewall.",
				References:  []string{"https://www.cisecurity.org/insights/white-papers/cis-controls-v8"},
				Metadata:    meta,
			})
		}
	}

	// Check: high connection count per PID (MEDIUM, beaconing/scanning).
	const maxConns = 50
	emitted := make(map[int]bool)
	for _, rc := range resolved {
		pid := rc.pid
		if pid <= 0 || emitted[pid] {
			continue
		}
		if pidConns[pid] > maxConns {
			emitted[pid] = true
			name := rc.name
			loc := fmt.Sprintf("PID:%d (%s)", pid, name)
			title := fmt.Sprintf("High ESTABLISHED connection count from PID %d (%s)", pid, name)
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("connections", loc, title),
				Scanner:  "connections",
				Severity: scanner.SevMedium,
				Title:    title,
				Detail:   fmt.Sprintf("Process %q (PID %d) has %d ESTABLISHED TCP connections, which may indicate beaconing, port scanning, or a botnet payload.", name, pid, pidConns[pid]),
				Evidence: fmt.Sprintf("connection_count=%d", pidConns[pid]),
				Location: loc,
				Remediation: "Investigate the process and its network activity using 'ss -tp' or 'lsof -p <pid>'. Terminate if unexpected.",
				References:  []string{"https://attack.mitre.org/techniques/T1046/"},
				Metadata: map[string]string{
					"pid":              strconv.Itoa(pid),
					"process_name":     name,
					"connection_count": strconv.Itoa(pidConns[pid]),
				},
			})
		}
	}

	return findings, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// parseEstablished reads the configured /proc/net/tcp[6] files and returns all
// ESTABLISHED connections.
func (s *ConnectionsScanner) parseEstablished() []connEntry {
	var conns []connEntry
	for _, path := range s.procNetFiles {
		entries, err := parseProcNetTCPConns(path)
		if err != nil {
			continue
		}
		conns = append(conns, entries...)
	}
	return conns
}

// buildInodeMap scans /proc/*/fd/ symlinks to map socket inodes to PIDs and
// process names.
func (s *ConnectionsScanner) buildInodeMap() map[string]struct {
	pid  int
	name string
} {
	result := make(map[string]struct {
		pid  int
		name string
	})

	procGlob := filepath.Join(s.procRoot, "*", "fd", "*")
	links, err := filepath.Glob(procGlob)
	if err != nil {
		return result
	}

	for _, link := range links {
		target, err := os.Readlink(link)
		if err != nil {
			continue
		}
		// Symlinks to sockets look like: socket:[<inode>]
		if !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")

		// Extract PID from /proc/<pid>/fd/<n>
		parts := strings.Split(link, string(os.PathSeparator))
		// parts: ["", "proc", "<pid>", "fd", "<n>"]
		if len(parts) < 3 {
			continue
		}
		pidStr := parts[2]
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		if _, seen := result[inode]; !seen {
			result[inode] = struct {
				pid  int
				name string
			}{pid, getProcessName(pid)}
		}
	}

	return result
}

// parseProcNetTCPConns reads a /proc/net/tcp or /proc/net/tcp6 file and
// returns all entries in ESTABLISHED state (01).
func parseProcNetTCPConns(path string) ([]connEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []connEntry
	sc := bufio.NewScanner(f)

	// Skip header.
	sc.Scan()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		entry, ok := extractEstablishedConn(line)
		if !ok {
			continue
		}
		conns = append(conns, entry)
	}
	return conns, sc.Err()
}

// extractEstablishedConn parses one data line from /proc/net/tcp[6] and returns
// a connEntry if the socket is in ESTABLISHED state (01).
//
// /proc/net/tcp line format:
//
//	sl  local_address rem_address   st tx_queue:rx_queue ...  inode
//	 0  0100007F:0016 0101010A:115C 01 ...                    98765
func extractEstablishedConn(line string) (connEntry, bool) {
	fields := strings.Fields(line)
	// We need at least: sl(0) local(1) remote(2) state(3) ... inode(9)
	if len(fields) < 10 {
		return connEntry{}, false
	}

	state := strings.ToUpper(strings.TrimSpace(fields[3]))
	if state != strings.ToUpper(tcpEstablishedState) {
		return connEntry{}, false
	}

	localIP, localPort, ok := parseHexAddr(fields[1])
	if !ok {
		return connEntry{}, false
	}
	remoteIP, remotePort, ok := parseHexAddr(fields[2])
	if !ok {
		return connEntry{}, false
	}

	// inode is field index 9.
	inode := strings.TrimSpace(fields[9])

	return connEntry{
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		inode:      inode,
	}, true
}

// parseHexAddr splits "HHHHHHHH:HHHH" (or IPv6 variant) into IP string and
// port number.
func parseHexAddr(addr string) (ip string, port uint16, ok bool) {
	colonIdx := strings.LastIndex(addr, ":")
	if colonIdx < 0 {
		return "", 0, false
	}
	hexIP := addr[:colonIdx]
	hexPort := addr[colonIdx+1:]

	ip = parseHexIP(hexIP)
	port = parseHexPort(hexPort)
	return ip, port, true
}

// parseHexIP converts a little-endian hex IPv4 address from /proc/net/tcp to a
// dotted-decimal string.
//
// Example: "0100007F" → "127.0.0.1"
// IPv6 addresses (32 hex chars) are returned as a joined group string.
func parseHexIP(hexStr string) string {
	if len(hexStr) == 8 {
		// IPv4: 4 bytes stored in little-endian order.
		b, err := strconv.ParseUint(hexStr, 16, 32)
		if err != nil {
			return hexStr
		}
		v := uint32(b)
		return fmt.Sprintf("%d.%d.%d.%d",
			v&0xFF,
			(v>>8)&0xFF,
			(v>>16)&0xFF,
			(v>>24)&0xFF,
		)
	}
	if len(hexStr) == 32 {
		// IPv6: four 32-bit words, each in little-endian.
		var groups []string
		for i := 0; i < 32; i += 8 {
			b, err := strconv.ParseUint(hexStr[i:i+8], 16, 32)
			if err != nil {
				return hexStr
			}
			v := uint32(b)
			groups = append(groups, fmt.Sprintf("%02x%02x:%02x%02x",
				v&0xFF, (v>>8)&0xFF, (v>>16)&0xFF, (v>>24)&0xFF))
		}
		return strings.Join(groups, ":")
	}
	return hexStr
}

// parseHexPort converts a 4-character big-endian hex port string to uint16.
func parseHexPort(hexStr string) uint16 {
	v, err := strconv.ParseUint(hexStr, 16, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}

// getProcessName reads /proc/<pid>/comm to return the process name.
func getProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// readProcessExe resolves the /proc/<pid>/exe symlink to get the executable path.
func readProcessExe(pid int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return target
}

// ---------------------------------------------------------------------------
// Exported helpers for testing
// ---------------------------------------------------------------------------

// ParseHexIPExported is an exported wrapper around parseHexIP for use in tests.
func ParseHexIPExported(hex string) string {
	return parseHexIP(hex)
}

// ConnEntryExported is an exported view of a parsed /proc/net/tcp connection
// entry, used only in tests.
type ConnEntryExported struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Inode      string
}

// ParseProcNetTCPConnsFile reads a file in /proc/net/tcp format and returns all
// ESTABLISHED connections as exported structs. Exported for direct testing with
// synthetic files.
func ParseProcNetTCPConnsFile(path string) ([]ConnEntryExported, error) {
	raw, err := parseProcNetTCPConns(path)
	if err != nil {
		return nil, err
	}
	out := make([]ConnEntryExported, len(raw))
	for i, c := range raw {
		out[i] = ConnEntryExported{
			LocalIP:    c.localIP,
			LocalPort:  c.localPort,
			RemoteIP:   c.remoteIP,
			RemotePort: c.remotePort,
			Inode:      c.inode,
		}
	}
	return out, nil
}
