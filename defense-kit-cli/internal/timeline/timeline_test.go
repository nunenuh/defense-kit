package timeline_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/timeline"
)

// ---------------------------------------------------------------------------
// BuildTimeline
// ---------------------------------------------------------------------------

// TestBuildTimeline_SortsByTime verifies that BuildTimeline returns events
// ordered oldest-first regardless of the input order.
func TestBuildTimeline_SortsByTime(t *testing.T) {
	now := time.Now()
	earliest := now.Add(-2 * time.Hour)
	middle := now.Add(-1 * time.Hour)
	latest := now

	// Deliberately provide findings in reverse chronological order.
	findings := []scanner.Finding{
		{
			ID:       "f3",
			Scanner:  "connections",
			Severity: scanner.SevHigh,
			Title:    "Outbound connection",
			Metadata: map[string]string{"timestamp": latest.Format(time.RFC3339)},
		},
		{
			ID:       "f1",
			Scanner:  "persistence",
			Severity: scanner.SevMedium,
			Title:    "Cron job added",
			Metadata: map[string]string{"timestamp": earliest.Format(time.RFC3339)},
		},
		{
			ID:       "f2",
			Scanner:  "auth",
			Severity: scanner.SevLow,
			Title:    "Login event",
			Metadata: map[string]string{"timestamp": middle.Format(time.RFC3339)},
		},
	}

	events := timeline.BuildTimeline(findings)

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Events must be ordered oldest → newest.
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Errorf("event[%d] (%v) is before event[%d] (%v) — not sorted",
				i, events[i].Timestamp, i-1, events[i-1].Timestamp)
		}
	}

	// Verify the correct finding is first.
	if events[0].Finding.ID != "f1" {
		t.Errorf("first event should be f1 (earliest), got %q", events[0].Finding.ID)
	}
	if events[2].Finding.ID != "f3" {
		t.Errorf("last event should be f3 (latest), got %q", events[2].Finding.ID)
	}
}

// TestBuildTimeline_EmptyInput verifies that an empty input produces an empty
// (non-nil) slice.
func TestBuildTimeline_EmptyInput(t *testing.T) {
	events := timeline.BuildTimeline(nil)
	if events == nil {
		t.Error("BuildTimeline(nil) should not return nil")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for empty input, got %d", len(events))
	}
}

// TestBuildTimeline_FallbackTimestamp verifies that a finding without an
// explicit timestamp still appears in the timeline (using the fallback).
func TestBuildTimeline_FallbackTimestamp(t *testing.T) {
	findings := []scanner.Finding{
		{
			ID:      "no-meta",
			Scanner: "ports",
			Title:   "Unusual port",
			// No Metadata — should fall back to time.Now().
		},
	}

	events := timeline.BuildTimeline(findings)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Finding.ID != "no-meta" {
		t.Errorf("unexpected finding ID: %q", events[0].Finding.ID)
	}
	// Timestamp should be within the last minute (fallback = time.Now()).
	if time.Since(events[0].Timestamp) > time.Minute {
		t.Errorf("fallback timestamp is too old: %v", events[0].Timestamp)
	}
}

// TestBuildTimeline_SourceMatchesScanner verifies that TimelineEvent.Source
// is set from Finding.Scanner.
func TestBuildTimeline_SourceMatchesScanner(t *testing.T) {
	now := time.Now()
	findings := []scanner.Finding{
		{
			ID:       "f-scan",
			Scanner:  "connections",
			Metadata: map[string]string{"timestamp": now.Format(time.RFC3339)},
		},
	}
	events := timeline.BuildTimeline(findings)
	if events[0].Source != "connections" {
		t.Errorf("Source = %q, want %q", events[0].Source, "connections")
	}
}

// ---------------------------------------------------------------------------
// DetectChains
// ---------------------------------------------------------------------------

// TestDetectChains_FindsPersistenceC2 verifies that a persistence finding
// followed within 1 hour by a C2 connection finding produces an AttackChain.
func TestDetectChains_FindsPersistenceC2(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		{
			Timestamp: now,
			Source:    "cron",
			Finding: scanner.Finding{
				ID:      "p1",
				Scanner: "cron",
				Title:   "Cron job added to /etc/cron.d",
				Detail:  "A new cron job entry was found in /etc/cron.d/malware",
			},
		},
		{
			Timestamp: now.Add(30 * time.Minute),
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "c1",
				Scanner: "connections",
				Title:   "Outbound connection to suspicious remote",
				Detail:  "Process has an outbound TCP connection",
			},
		},
	}

	chains := timeline.DetectChains(events)
	if len(chains) == 0 {
		t.Fatal("expected at least one AttackChain for persistence+C2 pattern, got none")
	}

	found := false
	for _, ch := range chains {
		if len(ch.Events) >= 2 && ch.Confidence > 0 {
			found = true
			if ch.Description == "" {
				t.Error("AttackChain.Description should not be empty")
			}
			if ch.Confidence <= 0 || ch.Confidence > 1 {
				t.Errorf("Confidence = %v, want value in (0, 1]", ch.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("no valid AttackChain produced: %+v", chains)
	}
}

// TestDetectChains_NoPersistenceC2WhenOutsideWindow verifies that a persistence
// finding more than 1 hour before a connection does not produce a chain.
func TestDetectChains_NoPersistenceC2WhenOutsideWindow(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		{
			Timestamp: now,
			Source:    "cron",
			Finding: scanner.Finding{
				ID:      "p1",
				Scanner: "cron",
				Title:   "Cron job added",
			},
		},
		{
			Timestamp: now.Add(2 * time.Hour), // outside 1-hour window
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "c1",
				Scanner: "connections",
				Title:   "Outbound connection to suspicious remote",
			},
		},
	}

	chains := timeline.DetectChains(events)
	for _, ch := range chains {
		// The persistence+C2 chain should NOT be detected.
		for _, e := range ch.Events {
			if e.Finding.ID == "p1" {
				t.Errorf("should not detect persistence+C2 chain when events are >1h apart: %+v", ch)
			}
		}
	}
}

// TestDetectChains_DetectsCredentialExfil verifies the credential theft +
// exfiltration pattern.
func TestDetectChains_DetectsCredentialExfil(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		{
			Timestamp: now,
			Source:    "auth",
			Finding: scanner.Finding{
				ID:      "cr1",
				Scanner: "auth",
				Title:   "Credential exposure detected",
				Detail:  "Hardcoded password found in configuration file",
			},
		},
		{
			Timestamp: now.Add(45 * time.Minute),
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "ex1",
				Scanner: "connections",
				Title:   "Outbound connection to remote host",
			},
		},
	}

	chains := timeline.DetectChains(events)
	found := false
	for _, ch := range chains {
		if ch.Confidence > 0 && len(ch.Events) >= 2 {
			found = true
		}
	}
	if !found {
		t.Error("expected an AttackChain for credential+exfil pattern, got none")
	}
}

// TestDetectChains_DetectsPrivEsc verifies the SUID + UID-0 privilege
// escalation pattern.
func TestDetectChains_DetectsPrivEsc(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		{
			Timestamp: now,
			Source:    "filesystem",
			Finding: scanner.Finding{
				ID:      "s1",
				Scanner: "filesystem",
				Title:   "World-writable SUID binary found",
				Detail:  "A setuid binary is world-writable, enabling privilege escalation",
			},
		},
		{
			Timestamp: now.Add(10 * time.Minute),
			Source:    "process",
			Finding: scanner.Finding{
				ID:      "u1",
				Scanner: "process",
				Title:   "Process running with uid=0",
				Detail:  "Unexpected process running as root user (uid 0)",
			},
		},
	}

	chains := timeline.DetectChains(events)
	found := false
	for _, ch := range chains {
		if ch.Confidence > 0 && len(ch.Events) >= 2 {
			found = true
		}
	}
	if !found {
		t.Error("expected an AttackChain for privilege escalation pattern, got none")
	}
}

// TestDetectChains_EmptyInput verifies that DetectChains returns an empty
// (non-nil) slice for empty input.
func TestDetectChains_EmptyInput(t *testing.T) {
	chains := timeline.DetectChains(nil)
	if chains == nil {
		// Nil is also acceptable — just ensure no panic.
		t.Log("DetectChains(nil) returned nil (acceptable)")
	}
}

// ---------------------------------------------------------------------------
// Additional BuildTimeline tests
// ---------------------------------------------------------------------------

// TestBuildTimeline_MetadataTimestamp verifies that a finding with a
// "timestamp" key in Metadata gets the correct timestamp in the event.
func TestBuildTimeline_MetadataTimestamp(t *testing.T) {
	ref := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)

	findings := []scanner.Finding{
		{
			ID:      "meta-ts",
			Scanner: "cron",
			Title:   "Cron modification",
			Metadata: map[string]string{
				"timestamp": ref.Format(time.RFC3339),
			},
		},
	}

	events := timeline.BuildTimeline(findings)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Timestamp.Equal(ref) {
		t.Errorf("expected timestamp %v, got %v", ref, events[0].Timestamp)
	}
}

// TestBuildTimeline_MetadataUnixTimestamp verifies that a Unix epoch string
// in Metadata["timestamp"] is parsed correctly.
func TestBuildTimeline_MetadataUnixTimestamp(t *testing.T) {
	epoch := int64(1700000000)
	ref := time.Unix(epoch, 0)

	findings := []scanner.Finding{
		{
			ID:      "unix-ts",
			Scanner: "process",
			Title:   "Suspicious process",
			Metadata: map[string]string{
				"timestamp": "1700000000",
			},
		},
	}

	events := timeline.BuildTimeline(findings)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Timestamp.Equal(ref) {
		t.Errorf("expected unix timestamp %v, got %v", ref, events[0].Timestamp)
	}
}

// TestBuildTimeline_FileLocation verifies that a finding whose Location is an
// existing filesystem path gets a timestamp from the file's mtime (not fallback).
func TestBuildTimeline_FileLocation(t *testing.T) {
	// Create a temp file to use as a realistic Location.
	tmpDir := t.TempDir()
	tmpFile := tmpDir + "/test-finding-location.txt"
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	before := time.Now().Add(-time.Second)

	findings := []scanner.Finding{
		{
			ID:       "file-loc",
			Scanner:  "filesystem",
			Title:    "Suspicious file",
			Location: tmpFile,
		},
	}

	events := timeline.BuildTimeline(findings)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// The timestamp should reflect the file's mtime, which is >= before.
	if events[0].Timestamp.Before(before) {
		t.Errorf("file-location timestamp %v is older than expected (before=%v)", events[0].Timestamp, before)
	}
}

// TestBuildTimeline_SortsChronologically verifies oldest-first ordering with
// multiple findings across a wide time range.
func TestBuildTimeline_SortsChronologically(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Intentionally out of order: t+3h, t+0h, t+1h, t+2h
	findings := []scanner.Finding{
		{
			ID:       "f4",
			Scanner:  "network",
			Title:    "Event 4",
			Metadata: map[string]string{"timestamp": base.Add(3 * time.Hour).Format(time.RFC3339)},
		},
		{
			ID:       "f1",
			Scanner:  "cron",
			Title:    "Event 1",
			Metadata: map[string]string{"timestamp": base.Format(time.RFC3339)},
		},
		{
			ID:       "f3",
			Scanner:  "auth",
			Title:    "Event 3",
			Metadata: map[string]string{"timestamp": base.Add(2 * time.Hour).Format(time.RFC3339)},
		},
		{
			ID:       "f2",
			Scanner:  "process",
			Title:    "Event 2",
			Metadata: map[string]string{"timestamp": base.Add(1 * time.Hour).Format(time.RFC3339)},
		},
	}

	events := timeline.BuildTimeline(findings)
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	expectedOrder := []string{"f1", "f2", "f3", "f4"}
	for i, id := range expectedOrder {
		if events[i].Finding.ID != id {
			t.Errorf("event[%d]: expected ID=%s, got ID=%s", i, id, events[i].Finding.ID)
		}
	}

	// Also verify strictly ascending.
	for i := 1; i < len(events); i++ {
		if !events[i].Timestamp.After(events[i-1].Timestamp) {
			t.Errorf("events not in ascending order at index %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional DetectChains tests
// ---------------------------------------------------------------------------

// TestDetectChains_SingleFinding verifies that a single finding produces no chain.
func TestDetectChains_SingleFinding(t *testing.T) {
	events := []timeline.TimelineEvent{
		{
			Timestamp: time.Now(),
			Source:    "cron",
			Finding: scanner.Finding{
				ID:      "solo",
				Scanner: "cron",
				Title:   "Cron job added",
			},
		},
	}

	chains := timeline.DetectChains(events)
	if len(chains) != 0 {
		t.Errorf("expected 0 chains for a single finding, got %d: %+v", len(chains), chains)
	}
}

// TestDetectChains_AllPatterns exercises persistence+C2, credential+exfil,
// and privesc patterns with a single combined event set.
func TestDetectChains_AllPatterns(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		// Persistence event
		{
			Timestamp: now,
			Source:    "persistence",
			Finding: scanner.Finding{
				ID:      "persist1",
				Scanner: "persistence",
				Title:   "Startup persistence added",
				Detail:  "Entry added to rc.local",
			},
		},
		// C2 connection (within 1h of persistence)
		{
			Timestamp: now.Add(20 * time.Minute),
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "c2-1",
				Scanner: "connections",
				Title:   "Outbound C2 connection detected",
			},
		},
		// Credential event
		{
			Timestamp: now.Add(30 * time.Minute),
			Source:    "credential",
			Finding: scanner.Finding{
				ID:      "cred1",
				Scanner: "credential",
				Title:   "SSH key exposure",
				Detail:  "ssh key found in world-readable location",
			},
		},
		// Exfil connection (within 2h of credential)
		{
			Timestamp: now.Add(1*time.Hour + 30*time.Minute),
			Source:    "network",
			Finding: scanner.Finding{
				ID:      "exfil1",
				Scanner: "network",
				Title:   "Outbound connection to remote",
			},
		},
		// SUID event
		{
			Timestamp: now.Add(2 * time.Hour),
			Source:    "filesystem",
			Finding: scanner.Finding{
				ID:      "suid1",
				Scanner: "filesystem",
				Title:   "Unexpected SUID binary",
				Detail:  "setuid bit set on /tmp/evil",
			},
		},
		// UID-0 event (within 30m of SUID)
		{
			Timestamp: now.Add(2*time.Hour + 10*time.Minute),
			Source:    "process",
			Finding: scanner.Finding{
				ID:      "uid0-1",
				Scanner: "process",
				Title:   "Process with elevated privilege",
				Detail:  "process running with uid=0 unexpectedly",
			},
		},
	}

	chains := timeline.DetectChains(events)
	if len(chains) < 3 {
		t.Errorf("expected at least 3 attack chains (persistence+C2, cred+exfil, privesc), got %d: %+v", len(chains), chains)
	}

	for _, ch := range chains {
		if ch.Description == "" {
			t.Error("AttackChain.Description must not be empty")
		}
		if ch.Confidence <= 0 || ch.Confidence > 1 {
			t.Errorf("Confidence %v out of range (0, 1]", ch.Confidence)
		}
		if len(ch.Events) < 2 {
			t.Errorf("AttackChain should have at least 2 events, got %d", len(ch.Events))
		}
	}
}

// TestDetectChains_OutsideTimeWindow — no chains when events are too far apart.
func TestDetectChains_OutsideTimeWindow(t *testing.T) {
	now := time.Now()

	events := []timeline.TimelineEvent{
		// Persistence event
		{
			Timestamp: now,
			Source:    "cron",
			Finding: scanner.Finding{
				ID:      "p-far",
				Scanner: "cron",
				Title:   "Cron job added",
			},
		},
		// C2 connection — 3 hours later (outside 1h window)
		{
			Timestamp: now.Add(3 * time.Hour),
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "c2-far",
				Scanner: "connections",
				Title:   "Outbound connection to suspicious remote",
			},
		},
		// Credential event
		{
			Timestamp: now.Add(4 * time.Hour),
			Source:    "auth",
			Finding: scanner.Finding{
				ID:      "cred-far",
				Scanner: "auth",
				Title:   "Credential exposure detected",
				Detail:  "password found in configuration",
			},
		},
		// Exfil connection — 4 hours after credential (outside 2h window)
		{
			Timestamp: now.Add(8 * time.Hour),
			Source:    "connections",
			Finding: scanner.Finding{
				ID:      "exfil-far",
				Scanner: "connections",
				Title:   "Outbound connection to remote host",
			},
		},
		// SUID event
		{
			Timestamp: now.Add(9 * time.Hour),
			Source:    "filesystem",
			Finding: scanner.Finding{
				ID:      "suid-far",
				Scanner: "filesystem",
				Title:   "SUID binary found",
				Detail:  "setuid capability set",
			},
		},
		// UID-0 event — 1 hour after SUID (outside 30m window)
		{
			Timestamp: now.Add(10 * time.Hour),
			Source:    "process",
			Finding: scanner.Finding{
				ID:      "uid0-far",
				Scanner: "process",
				Title:   "Process running as root",
				Detail:  "uid=0 process detected",
			},
		},
	}

	chains := timeline.DetectChains(events)
	if len(chains) != 0 {
		t.Errorf("expected 0 chains when all events are outside time windows, got %d: %+v", len(chains), chains)
	}
}

// ---------------------------------------------------------------------------
// parseTimestamp helper tests
// ---------------------------------------------------------------------------

func TestParseTimestamp_RFC3339(t *testing.T) {
	ref := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	s := ref.Format(time.RFC3339)
	got, err := timeline.ParseTimestamp(s)
	if err != nil {
		t.Fatalf("ParseTimestamp RFC3339: unexpected error: %v", err)
	}
	if !got.Equal(ref) {
		t.Errorf("got %v, want %v", got, ref)
	}
}

func TestParseTimestamp_RFC3339Nano(t *testing.T) {
	ref := time.Date(2024, 6, 1, 12, 0, 0, 123456789, time.UTC)
	s := ref.Format(time.RFC3339Nano)
	got, err := timeline.ParseTimestamp(s)
	if err != nil {
		t.Fatalf("ParseTimestamp RFC3339Nano: unexpected error: %v", err)
	}
	if !got.Equal(ref) {
		t.Errorf("got %v, want %v", got, ref)
	}
}

func TestParseTimestamp_UnixEpoch(t *testing.T) {
	epoch := int64(1700000000)
	ref := time.Unix(epoch, 0)
	got, err := timeline.ParseTimestamp("1700000000")
	if err != nil {
		t.Fatalf("ParseTimestamp unix: unexpected error: %v", err)
	}
	if !got.Equal(ref) {
		t.Errorf("got %v, want %v", got, ref)
	}
}

func TestParseTimestamp_Invalid(t *testing.T) {
	_, err := timeline.ParseTimestamp("not-a-timestamp")
	if err == nil {
		t.Error("expected error for invalid timestamp string, got nil")
	}
}

// ---------------------------------------------------------------------------
// parsePIDFromLocation helper tests
// ---------------------------------------------------------------------------

func TestParsePIDFromLocation_Simple(t *testing.T) {
	pid, err := timeline.ParsePIDFromLocation("PID:1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 1234 {
		t.Errorf("expected pid=1234, got %d", pid)
	}
}

func TestParsePIDFromLocation_WithName(t *testing.T) {
	pid, err := timeline.ParsePIDFromLocation("PID:5678 (bash)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 5678 {
		t.Errorf("expected pid=5678, got %d", pid)
	}
}

func TestParsePIDFromLocation_Empty(t *testing.T) {
	_, err := timeline.ParsePIDFromLocation("PID:")
	if err == nil {
		t.Error("expected error for empty PID, got nil")
	}
}

func TestParsePIDFromLocation_NotANumber(t *testing.T) {
	_, err := timeline.ParsePIDFromLocation("PID:notanumber")
	if err == nil {
		t.Error("expected error for non-numeric PID, got nil")
	}
}

// ---------------------------------------------------------------------------
// readBootTime helper test (Linux /proc/stat)
// ---------------------------------------------------------------------------

func TestReadBootTime_Linux(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); os.IsNotExist(err) {
		t.Skip("skipping: /proc/stat not available")
	}
	btime, err := timeline.ReadBootTime()
	if err != nil {
		t.Fatalf("ReadBootTime returned error: %v", err)
	}
	if btime <= 0 {
		t.Errorf("expected positive boot time, got %d", btime)
	}
}

// ---------------------------------------------------------------------------
// newLineScanner helper test
// ---------------------------------------------------------------------------

func TestNewLineScanner_ReadsLines(t *testing.T) {
	content := "line one\nline two\nline three\n"
	r := strings.NewReader(content)
	sc := timeline.NewLineScanner(r)

	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "line one" {
		t.Errorf("lines[0] = %q, want %q", lines[0], "line one")
	}
}

// ---------------------------------------------------------------------------
// Event classifier helper tests — covering remaining keyword branches
// ---------------------------------------------------------------------------

func TestIsPersistenceEvent_BySourceKeywords(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"cron", true},
		{"persistence", true},
		{"systemd", true},
		{"unrelated", false},
	}
	for _, tc := range cases {
		e := timeline.TimelineEvent{
			Source:  tc.src,
			Finding: scanner.Finding{Title: "irrelevant", Detail: "irrelevant"},
		}
		got := timeline.IsPersistenceEvent(e)
		if got != tc.want {
			t.Errorf("IsPersistenceEvent(src=%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestIsPersistenceEvent_ByTitleKeywords(t *testing.T) {
	keywords := []string{"cron", "systemd", "rc.local", "init.d", "autostart", "persistence", "startup"}
	for _, kw := range keywords {
		e := timeline.TimelineEvent{
			Source:  "unknown",
			Finding: scanner.Finding{Title: "Found " + kw + " entry"},
		}
		if !timeline.IsPersistenceEvent(e) {
			t.Errorf("IsPersistenceEvent: expected true for title containing %q", kw)
		}
	}
}

func TestIsConnectionEvent_BySourceKeywords(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"connection", true},
		{"network", true},
		{"threat_intel", true},
		{"filesystem", false},
	}
	for _, tc := range cases {
		e := timeline.TimelineEvent{
			Source:  tc.src,
			Finding: scanner.Finding{Title: "irrelevant"},
		}
		got := timeline.IsConnectionEvent(e)
		if got != tc.want {
			t.Errorf("IsConnectionEvent(src=%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestIsConnectionEvent_ByTitleKeywords(t *testing.T) {
	keywords := []string{"outbound", "connection", "c2", "malicious ip", "port", "remote"}
	for _, kw := range keywords {
		e := timeline.TimelineEvent{
			Source:  "unknown",
			Finding: scanner.Finding{Title: "Alert: " + kw + " detected"},
		}
		if !timeline.IsConnectionEvent(e) {
			t.Errorf("IsConnectionEvent: expected true for title containing %q", kw)
		}
	}
}

func TestIsCredentialEvent_BySourceKeywords(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"credential", true},
		{"auth", true},
		{"secret", true},
		{"process", false},
	}
	for _, tc := range cases {
		e := timeline.TimelineEvent{
			Source:  tc.src,
			Finding: scanner.Finding{Title: "irrelevant"},
		}
		got := timeline.IsCredentialEvent(e)
		if got != tc.want {
			t.Errorf("IsCredentialEvent(src=%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestIsCredentialEvent_ByTitleKeywords(t *testing.T) {
	keywords := []string{"credential", "password", "secret", "ssh key", "api key", "token", "passphrase"}
	for _, kw := range keywords {
		e := timeline.TimelineEvent{
			Source:  "unknown",
			Finding: scanner.Finding{Title: "Exposed " + kw + " found"},
		}
		if !timeline.IsCredentialEvent(e) {
			t.Errorf("IsCredentialEvent: expected true for title containing %q", kw)
		}
	}
}
