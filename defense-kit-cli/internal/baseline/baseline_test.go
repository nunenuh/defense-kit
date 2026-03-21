package baseline_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/baseline"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

func makeFindings() []scanner.Finding {
	return []scanner.Finding{
		{
			ID:       "finding-001",
			Scanner:  "test-scanner",
			Severity: scanner.SevHigh,
			Title:    "Test Finding One",
			Detail:   "Detail one",
		},
		{
			ID:       "finding-002",
			Scanner:  "test-scanner",
			Severity: scanner.SevMedium,
			Title:    "Test Finding Two",
			Detail:   "Detail two",
		},
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	b := baseline.Baseline{
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		Host:         "test-host",
		ScanID:       "scan-abc123",
		Findings:     makeFindings(),
		Acknowledged: []string{"finding-001"},
	}

	if err := baseline.Save(path, b); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != 1 {
		t.Errorf("expected version=1, got %d", loaded.Version)
	}
	if loaded.Host != b.Host {
		t.Errorf("expected host=%q, got %q", b.Host, loaded.Host)
	}
	if loaded.ScanID != b.ScanID {
		t.Errorf("expected scan_id=%q, got %q", b.ScanID, loaded.ScanID)
	}
	if len(loaded.Findings) != len(b.Findings) {
		t.Errorf("expected %d findings, got %d", len(b.Findings), len(loaded.Findings))
	}
	if len(loaded.Acknowledged) != len(b.Acknowledged) {
		t.Errorf("expected %d acknowledged, got %d", len(b.Acknowledged), len(loaded.Acknowledged))
	}
	if !loaded.CreatedAt.Equal(b.CreatedAt) {
		t.Errorf("expected created_at=%v, got %v", b.CreatedAt, loaded.CreatedAt)
	}
}

func TestDiff(t *testing.T) {
	// old has finding-001 and finding-002
	// current has finding-001 (same) and finding-003 (new)
	// expected: 1 new (finding-003), 1 resolved (finding-002), 1 unchanged (finding-001)
	old := baseline.Baseline{
		Findings: []scanner.Finding{
			{ID: "finding-001", Severity: scanner.SevHigh, Title: "Finding One"},
			{ID: "finding-002", Severity: scanner.SevMedium, Title: "Finding Two"},
		},
	}

	current := []scanner.Finding{
		{ID: "finding-001", Severity: scanner.SevHigh, Title: "Finding One"},
		{ID: "finding-003", Severity: scanner.SevLow, Title: "Finding Three"},
	}

	result := baseline.Diff(old, current)

	if len(result.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(result.New))
	} else if result.New[0].ID != "finding-003" {
		t.Errorf("expected new finding ID=finding-003, got %q", result.New[0].ID)
	}

	if len(result.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(result.Resolved))
	} else if result.Resolved[0].ID != "finding-002" {
		t.Errorf("expected resolved finding ID=finding-002, got %q", result.Resolved[0].ID)
	}

	if len(result.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged finding, got %d", len(result.Unchanged))
	} else if result.Unchanged[0].ID != "finding-001" {
		t.Errorf("expected unchanged finding ID=finding-001, got %q", result.Unchanged[0].ID)
	}

	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed findings, got %d", len(result.Changed))
	}
}

func TestDiffChanged(t *testing.T) {
	// same ID but different severity → appears in Changed
	old := baseline.Baseline{
		Findings: []scanner.Finding{
			{ID: "finding-001", Severity: scanner.SevLow, Title: "Finding One"},
		},
	}

	current := []scanner.Finding{
		{ID: "finding-001", Severity: scanner.SevCritical, Title: "Finding One"},
	}

	result := baseline.Diff(old, current)

	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed finding, got %d", len(result.Changed))
	}

	change := result.Changed[0]
	if change.Finding.ID != "finding-001" {
		t.Errorf("expected changed finding ID=finding-001, got %q", change.Finding.ID)
	}
	if change.OldSeverity != scanner.SevLow {
		t.Errorf("expected old severity=SevLow, got %v", change.OldSeverity)
	}
	if change.Finding.Severity != scanner.SevCritical {
		t.Errorf("expected new severity=SevCritical, got %v", change.Finding.Severity)
	}

	if len(result.New) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(result.New))
	}
	if len(result.Resolved) != 0 {
		t.Errorf("expected 0 resolved findings, got %d", len(result.Resolved))
	}
	if len(result.Unchanged) != 0 {
		t.Errorf("expected 0 unchanged findings, got %d", len(result.Unchanged))
	}
}

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}

	if b.Version != 0 {
		t.Errorf("expected version=0 for empty baseline, got %d", b.Version)
	}
	if len(b.Findings) != 0 {
		t.Errorf("expected 0 findings for empty baseline, got %d", len(b.Findings))
	}

	// ensure path truly doesn't exist
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("test file should not exist")
	}
}
