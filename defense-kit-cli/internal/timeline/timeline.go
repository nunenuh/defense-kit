// Package timeline correlates security findings across scanners by timestamp,
// orders them chronologically, and detects known multi-step attack patterns.
package timeline

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// TimelineEvent associates a scanner finding with a timestamp and the name of
// the data source that produced it.
type TimelineEvent struct {
	Timestamp time.Time
	Finding   scanner.Finding
	// Source is the scanner name or data source (e.g., "cron", "connections").
	Source string
}

// AttackChain groups a sequence of timeline events that together form a
// recognised multi-step attack pattern.
type AttackChain struct {
	Events      []TimelineEvent
	Description string
	// Confidence is a value in [0.0, 1.0] that reflects how certain the
	// detection is.  Higher values mean stronger evidence.
	Confidence float64
}

// BuildTimeline extracts timestamps from findings and returns them sorted
// oldest-first.
//
// Timestamp resolution strategy (in order of preference):
//  1. "timestamp" key in Finding.Metadata (RFC 3339 / Unix epoch string).
//  2. File mtime of Finding.Location if it is a plain filesystem path.
//  3. Process start time from /proc/<pid>/stat when Location starts with
//     "PID:" and the /proc filesystem is available.
//  4. Current time (fallback — so every finding always appears in the result).
func BuildTimeline(findings []scanner.Finding) []TimelineEvent {
	events := make([]TimelineEvent, 0, len(findings))
	for _, f := range findings {
		ts := extractTimestamp(f)
		events = append(events, TimelineEvent{
			Timestamp: ts,
			Finding:   f,
			Source:    f.Scanner,
		})
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events
}

// DetectChains scans the ordered list of events for known multi-step attack
// patterns and returns any chains found.
func DetectChains(events []TimelineEvent) []AttackChain {
	var chains []AttackChain
	chains = append(chains, detectPersistenceC2(events)...)
	chains = append(chains, detectCredentialExfil(events)...)
	chains = append(chains, detectPrivEsc(events)...)
	return chains
}

// ---------------------------------------------------------------------------
// Pattern detectors
// ---------------------------------------------------------------------------

// detectPersistenceC2 looks for a cron/systemd persistence finding followed
// by an outbound connection finding within a 1-hour window.
//
// Pattern: "Persistence + C2"
func detectPersistenceC2(events []TimelineEvent) []AttackChain {
	const window = time.Hour

	var chains []AttackChain
	for i, e := range events {
		if !isPersistenceEvent(e) {
			continue
		}
		// Look forward for a C2/connection event within the time window.
		for j := i + 1; j < len(events); j++ {
			c2 := events[j]
			if c2.Timestamp.Sub(e.Timestamp) > window {
				break
			}
			if !isConnectionEvent(c2) {
				continue
			}
			chains = append(chains, AttackChain{
				Events:      []TimelineEvent{e, c2},
				Description: fmt.Sprintf("Persistence mechanism (%s) detected followed by C2/outbound connection (%s) within 1 hour", e.Finding.Title, c2.Finding.Title),
				Confidence:  0.75,
			})
		}
	}
	return chains
}

// detectCredentialExfil looks for a credential-related finding followed by an
// outbound connection finding within a 2-hour window.
//
// Pattern: "Credential theft + exfiltration"
func detectCredentialExfil(events []TimelineEvent) []AttackChain {
	const window = 2 * time.Hour

	var chains []AttackChain
	for i, e := range events {
		if !isCredentialEvent(e) {
			continue
		}
		for j := i + 1; j < len(events); j++ {
			conn := events[j]
			if conn.Timestamp.Sub(e.Timestamp) > window {
				break
			}
			if !isConnectionEvent(conn) {
				continue
			}
			chains = append(chains, AttackChain{
				Events:      []TimelineEvent{e, conn},
				Description: fmt.Sprintf("Credential access (%s) followed by outbound connection suggesting exfiltration (%s)", e.Finding.Title, conn.Finding.Title),
				Confidence:  0.70,
			})
		}
	}
	return chains
}

// detectPrivEsc looks for a SUID/capability finding and a UID-0 related finding
// that occur within a 30-minute window of each other (in either order).
//
// Pattern: "Privilege escalation"
func detectPrivEsc(events []TimelineEvent) []AttackChain {
	const window = 30 * time.Minute

	var chains []AttackChain
	for i, e := range events {
		if !isSUIDEvent(e) {
			continue
		}
		for j := 0; j < len(events); j++ {
			if j == i {
				continue
			}
			uid0 := events[j]
			if !isUID0Event(uid0) {
				continue
			}
			diff := e.Timestamp.Sub(uid0.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff > window {
				continue
			}
			chains = append(chains, AttackChain{
				Events:      []TimelineEvent{e, uid0},
				Description: fmt.Sprintf("Privilege escalation indicated by SUID/capability finding (%s) and UID-0 activity (%s) within 30 minutes", e.Finding.Title, uid0.Finding.Title),
				Confidence:  0.65,
			})
		}
	}
	return chains
}

// ---------------------------------------------------------------------------
// Event classifiers
// ---------------------------------------------------------------------------

func isPersistenceEvent(e TimelineEvent) bool {
	src := strings.ToLower(e.Source)
	title := strings.ToLower(e.Finding.Title)
	detail := strings.ToLower(e.Finding.Detail)

	if strings.Contains(src, "cron") || strings.Contains(src, "persistence") ||
		strings.Contains(src, "systemd") {
		return true
	}
	for _, kw := range []string{"cron", "systemd", "rc.local", "init.d", "autostart", "persistence", "startup"} {
		if strings.Contains(title, kw) || strings.Contains(detail, kw) {
			return true
		}
	}
	return false
}

func isConnectionEvent(e TimelineEvent) bool {
	src := strings.ToLower(e.Source)
	title := strings.ToLower(e.Finding.Title)

	if strings.Contains(src, "connection") || strings.Contains(src, "network") ||
		strings.Contains(src, "threat_intel") {
		return true
	}
	for _, kw := range []string{"outbound", "connection", "c2", "malicious ip", "port", "remote"} {
		if strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func isCredentialEvent(e TimelineEvent) bool {
	src := strings.ToLower(e.Source)
	title := strings.ToLower(e.Finding.Title)
	detail := strings.ToLower(e.Finding.Detail)

	if strings.Contains(src, "credential") || strings.Contains(src, "auth") ||
		strings.Contains(src, "secret") {
		return true
	}
	for _, kw := range []string{"credential", "password", "secret", "ssh key", "api key", "token", "passphrase"} {
		if strings.Contains(title, kw) || strings.Contains(detail, kw) {
			return true
		}
	}
	return false
}

func isSUIDEvent(e TimelineEvent) bool {
	title := strings.ToLower(e.Finding.Title)
	detail := strings.ToLower(e.Finding.Detail)

	for _, kw := range []string{"suid", "sgid", "setuid", "setgid", "capability", "cap_net_bind"} {
		if strings.Contains(title, kw) || strings.Contains(detail, kw) {
			return true
		}
	}
	return false
}

func isUID0Event(e TimelineEvent) bool {
	title := strings.ToLower(e.Finding.Title)
	detail := strings.ToLower(e.Finding.Detail)

	for _, kw := range []string{"uid 0", "uid=0", "root user", "root account", "privilege", "elevated"} {
		if strings.Contains(title, kw) || strings.Contains(detail, kw) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Timestamp extraction
// ---------------------------------------------------------------------------

// extractTimestamp attempts to find the most accurate timestamp for a finding.
func extractTimestamp(f scanner.Finding) time.Time {
	// 1. Explicit metadata timestamp.
	if ts, ok := f.Metadata["timestamp"]; ok {
		if t, err := parseTimestamp(ts); err == nil {
			return t
		}
	}

	// 2. File mtime if Location looks like an absolute path.
	if strings.HasPrefix(f.Location, "/") && !strings.HasPrefix(f.Location, "/proc") {
		// Location may contain extra context (e.g., "path:line"). Use the
		// first colon-separated segment that starts with "/".
		candidate := strings.SplitN(f.Location, ":", 2)[0]
		// Trim to a single path component (no trailing spaces / annotations).
		candidate = strings.Fields(candidate)[0]
		if fi, err := os.Stat(candidate); err == nil {
			return fi.ModTime()
		}
		// Try the directory too.
		dir := filepath.Dir(candidate)
		if fi, err := os.Stat(dir); err == nil {
			return fi.ModTime()
		}
	}

	// 3. Process start time from /proc/<pid>/stat.
	if strings.HasPrefix(f.Location, "PID:") {
		if pid, err := parsePIDFromLocation(f.Location); err == nil {
			if t, err := procStatStartTime(pid); err == nil {
				return t
			}
		}
	}

	// 4. Fallback: current time.
	return time.Now()
}

// parseTimestamp tries RFC 3339 first, then Unix epoch.
func parseTimestamp(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(epoch, 0), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp: %q", s)
}

// parsePIDFromLocation extracts the PID from a Location string of the form
// "PID:1234 (name)" or "PID:1234".
func parsePIDFromLocation(loc string) (int, error) {
	// Strip the "PID:" prefix.
	rest := strings.TrimPrefix(loc, "PID:")
	// Take everything up to the first space or parenthesis.
	pidStr := strings.FieldsFunc(rest, func(r rune) bool {
		return r == ' ' || r == '('
	})
	if len(pidStr) == 0 {
		return 0, fmt.Errorf("no PID in %q", loc)
	}
	return strconv.Atoi(pidStr[0])
}

// procStatStartTime reads /proc/<pid>/stat and returns the process start time
// expressed as a wall-clock time (using the system boot time + start-time ticks).
// If /proc is unavailable this returns an error.
func procStatStartTime(pid int) (time.Time, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}, err
	}

	// The start time is field 22 (0-indexed: 21) in /proc/<pid>/stat.
	// Fields after comm (field 2) may themselves contain spaces, so we find
	// the closing ')' first.
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return time.Time{}, fmt.Errorf("unexpected /proc stat format")
	}
	fields := strings.Fields(s[closeParen+1:])
	// Field 22 relative to the close-paren section is index 19 (fields after
	// state/ppid/pgrp/session/tty/tpgid/flags/minflt/cminflt/majflt/cmajflt/
	// utime/stime/cutime/cstime/priority/nice/num_threads/itrealvalue).
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return time.Time{}, fmt.Errorf("not enough fields in /proc stat")
	}
	startTicks, err := strconv.ParseUint(fields[startTimeIdx], 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	// Read boot time from /proc/stat.
	bootTime, err := readBootTime()
	if err != nil {
		return time.Time{}, err
	}

	const clkTck = 100 // USER_HZ — standard on Linux.
	startSecs := int64(startTicks) / clkTck
	return time.Unix(bootTime+startSecs, 0), nil
}

// readBootTime reads btime from /proc/stat.
func readBootTime() (int64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := newLineScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		return strconv.ParseInt(fields[1], 10, 64)
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}
