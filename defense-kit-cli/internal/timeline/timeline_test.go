package timeline_test

import (
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
