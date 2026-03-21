package hardener

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupFile copies the file at src into backupDir, naming the copy
// "{unix-timestamp}-{basename}". It returns the full path of the backup file.
func BackupFile(src, backupDir string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("backup: open source %q: %w", src, err)
	}
	defer in.Close()

	srcInfo, err := in.Stat()
	if err != nil {
		return "", fmt.Errorf("backup: stat source %q: %w", src, err)
	}

	backupName := fmt.Sprintf("%d-%s", time.Now().Unix(), filepath.Base(src))
	backupPath := filepath.Join(backupDir, backupName)

	out, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return "", fmt.Errorf("backup: create backup %q: %w", backupPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return "", fmt.Errorf("backup: copy %q → %q: %w", src, backupPath, err)
	}

	return backupPath, nil
}

// RestoreFile copies backupPath over originalPath, preserving the backup's
// file mode.
func RestoreFile(backupPath, originalPath string) error {
	in, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("restore: open backup %q: %w", backupPath, err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("restore: stat backup %q: %w", backupPath, err)
	}

	out, err := os.OpenFile(originalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("restore: open target %q: %w", originalPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("restore: copy %q → %q: %w", backupPath, originalPath, err)
	}

	return nil
}

// GenerateRollbackScript writes an executable bash script to path that, when
// run, restores every file mentioned in plan. Steps are written in forward
// order; execution order is the responsibility of the operator.
func GenerateRollbackScript(plan RollbackPlan, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("generate rollback script: create %q: %w", path, err)
	}
	defer f.Close()

	lines := []string{
		"#!/bin/bash",
		"set -euo pipefail",
		"",
		fmt.Sprintf("# Rollback script — session %s — %s", plan.SessionID, plan.Timestamp.Format(time.RFC3339)),
		"",
	}

	for _, step := range plan.Steps {
		lines = append(lines,
			fmt.Sprintf("echo %q", step.Description),
		)
		if step.BackupPath != "" {
			lines = append(lines,
				fmt.Sprintf("cp %q %q", step.BackupPath, step.Action.Target),
			)
		}
		lines = append(lines, "")
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return fmt.Errorf("generate rollback script: write: %w", err)
		}
	}

	return nil
}

// ExecuteRollback runs the rollback steps in plan in reverse order. For steps
// whose action type is FileEdit, FileCreate, or FileDelete and a BackupPath is
// set, RestoreFile is used. All errors are collected and returned; execution
// continues even after a step failure.
func ExecuteRollback(_ context.Context, plan RollbackPlan) []error {
	var errs []error

	// Iterate in reverse.
	for i := len(plan.Steps) - 1; i >= 0; i-- {
		step := plan.Steps[i]

		switch step.Action.Type {
		case FileEdit, FileCreate, FileDelete:
			if step.BackupPath != "" {
				if err := RestoreFile(step.BackupPath, step.Action.Target); err != nil {
					errs = append(errs, fmt.Errorf("rollback step %d (%s): %w", i, step.Description, err))
				}
			}
		case ServiceRestart, CommandExec:
			// Service and command rollback steps are handled by an external
			// orchestrator; nothing to execute here automatically.
		}
	}

	return errs
}
