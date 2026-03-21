package hardener

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// Engine orchestrates the hardening workflow: preview, approve, apply, verify,
// rollback, and script generation.
type Engine struct {
	registry  *HardenerRegistry
	outputDir string
}

// NewEngine returns an Engine that uses the given registry and writes rollback
// scripts to outputDir.
func NewEngine(registry *HardenerRegistry, outputDir string) *Engine {
	return &Engine{
		registry:  registry,
		outputDir: outputDir,
	}
}

// Run applies hardening fixes to the supplied findings according to opts.
// It returns one HardenResult per fixable finding. On a fatal apply error the
// function stops and returns the results collected so far together with the
// error.
func (e *Engine) Run(ctx context.Context, findings []scanner.Finding, opts HardenOptions) ([]HardenResult, error) {
	fixable := e.registry.FixableFindings(findings)

	var results []HardenResult
	var allRollbackSteps []RollbackStep

	for _, finding := range fixable {
		h, err := e.registry.FindHardener(finding)
		if err != nil {
			// Should not happen since FixableFindings already filtered, but be safe.
			continue
		}

		plan := h.Preview(finding)

		// Dry-run: record result without applying.
		if opts.DryRun || opts.Mode == ModeDryRun {
			results = append(results, HardenResult{
				Finding: finding,
				Plan:    plan,
				Applied: false,
			})
			continue
		}

		// AutoLow: skip HIGH and CRITICAL findings automatically.
		if opts.Mode == ModeAutoLow {
			if finding.Severity >= SevHigh {
				results = append(results, HardenResult{
					Finding: finding,
					Plan:    plan,
					Applied: false,
				})
				continue
			}
		}

		// Backup all FileEdit targets before applying.
		backupDir := e.outputDir
		if err := os.MkdirAll(backupDir, 0o755); err != nil {
			return results, fmt.Errorf("engine: create output dir %q: %w", backupDir, err)
		}

		for _, action := range plan.Actions {
			if action.Type == FileEdit {
				backupPath, backupErr := BackupFile(action.Target, backupDir)
				if backupErr != nil {
					// Non-fatal: log via result error and skip this backup.
					results = append(results, HardenResult{
						Finding: finding,
						Plan:    plan,
						Applied: false,
						Error:   fmt.Sprintf("backup failed for %s: %v", action.Target, backupErr),
					})
					goto nextFinding
				}
				if plan.BackupPaths == nil {
					plan.BackupPaths = make(map[string]string)
				}
				plan.BackupPaths[action.Target] = backupPath
			}
		}

		// Apply the fix.
		if applyErr := h.Apply(ctx, plan); applyErr != nil {
			results = append(results, HardenResult{
				Finding: finding,
				Plan:    plan,
				Applied: false,
				Error:   applyErr.Error(),
			})
			return results, fmt.Errorf("engine: apply failed for finding %q: %w", finding.ID, applyErr)
		}

		// Verify the fix.
		if verifyErr := h.Verify(ctx, plan); verifyErr != nil {
			// Rollback this specific fix.
			_ = h.Rollback(ctx, plan)
			results = append(results, HardenResult{
				Finding: finding,
				Plan:    plan,
				Applied: true,
				Error:   fmt.Sprintf("verify failed (rolled back): %v", verifyErr),
			})
			continue
		}

		// Collect rollback steps from the plan.
		allRollbackSteps = append(allRollbackSteps, plan.Rollback.Steps...)

		results = append(results, HardenResult{
			Finding:  finding,
			Plan:     plan,
			Applied:  true,
			Verified: true,
		})

	nextFinding:
	}

	// Generate a rollback script for all successfully applied fixes.
	if len(allRollbackSteps) > 0 {
		if mkErr := os.MkdirAll(e.outputDir, 0o755); mkErr == nil {
			ts := time.Now().Unix()
			scriptPath := filepath.Join(e.outputDir, fmt.Sprintf("rollback-%d.sh", ts))
			rollbackPlan := RollbackPlan{
				SessionID: fmt.Sprintf("session-%d", ts),
				Timestamp: time.Now(),
				Steps:     allRollbackSteps,
			}
			// Best-effort; ignore script generation errors so the caller still
			// receives the results.
			_ = GenerateRollbackScript(rollbackPlan, scriptPath)
		}
	}

	return results, nil
}

// SevHigh is the minimum severity at which ModeAutoLow will skip a finding.
// It mirrors scanner.SevHigh so engine.go does not need a type alias.
const SevHigh = scanner.SevHigh
