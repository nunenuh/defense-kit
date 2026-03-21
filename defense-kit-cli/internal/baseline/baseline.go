package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// Baseline represents a snapshot of security findings at a point in time.
type Baseline struct {
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	Host         string            `json:"host"`
	ScanID       string            `json:"scan_id"`
	Findings     []scanner.Finding `json:"findings"`
	Acknowledged []string          `json:"acknowledged"`
}

// DiffResult holds the categorized differences between an old baseline and a new scan.
type DiffResult struct {
	New       []scanner.Finding `json:"new"`
	Resolved  []scanner.Finding `json:"resolved"`
	Changed   []FindingChange   `json:"changed"`
	Unchanged []scanner.Finding `json:"unchanged"`
}

// FindingChange records a finding whose severity changed between baseline and current scan.
type FindingChange struct {
	Finding     scanner.Finding  `json:"finding"`
	OldSeverity scanner.Severity `json:"old_severity"`
}

// Save marshals the Baseline to JSON and writes it to path. Version is always set to 1.
func Save(path string, b Baseline) error {
	saved := b
	saved.Version = 1

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Load reads a Baseline from the JSON file at path.
// If the file does not exist, an empty Baseline is returned without error.
func Load(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Baseline{}, nil
		}
		return Baseline{}, err
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, err
	}
	return b, nil
}

// Diff compares old baseline findings against the current list of findings.
// Findings are matched by ID.
//   - New: present in current but not in old.
//   - Resolved: present in old but not in current.
//   - Changed: same ID but different severity (current finding stored with old severity recorded).
//   - Unchanged: same ID and same severity.
func Diff(old Baseline, current []scanner.Finding) DiffResult {
	oldByID := make(map[string]scanner.Finding, len(old.Findings))
	for _, f := range old.Findings {
		oldByID[f.ID] = f
	}

	currentByID := make(map[string]scanner.Finding, len(current))
	for _, f := range current {
		currentByID[f.ID] = f
	}

	result := DiffResult{
		New:       []scanner.Finding{},
		Resolved:  []scanner.Finding{},
		Changed:   []FindingChange{},
		Unchanged: []scanner.Finding{},
	}

	// Categorize current findings relative to old baseline.
	for _, f := range current {
		oldFinding, existed := oldByID[f.ID]
		if !existed {
			result.New = append(result.New, f)
			continue
		}
		if oldFinding.Severity != f.Severity {
			result.Changed = append(result.Changed, FindingChange{
				Finding:     f,
				OldSeverity: oldFinding.Severity,
			})
		} else {
			result.Unchanged = append(result.Unchanged, f)
		}
	}

	// Findings in old but absent from current are resolved.
	for _, f := range old.Findings {
		if _, stillPresent := currentByID[f.ID]; !stillPresent {
			result.Resolved = append(result.Resolved, f)
		}
	}

	return result
}
