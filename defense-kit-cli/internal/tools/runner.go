package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Runner executes external tools safely. No shell interpretation.
type Runner struct{}

// NewRunner creates a new Runner instance.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes the named tool with args using exec.CommandContext (no shell).
// Returns stdout bytes on success.
// Returns stdout bytes AND an error on failure, since some tools write findings
// to stdout even when they exit with a non-zero status.
func (r *Runner) Run(ctx context.Context, tool string, args []string) ([]byte, error) {
	stdout, _, err := r.RunWithStderr(ctx, tool, args)
	return stdout, err
}

// RunWithStderr executes the named tool and returns stdout, stderr, and any error.
// No shell is used; the binary is resolved via exec.LookPath.
func (r *Runner) RunWithStderr(ctx context.Context, tool string, args []string) (stdout, stderr []byte, err error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return nil, nil, fmt.Errorf("tool %q not found: %w", tool, err)
	}

	cmd := exec.CommandContext(ctx, path, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	stdout = stdoutBuf.Bytes()
	stderr = stderrBuf.Bytes()

	if runErr != nil {
		return stdout, stderr, fmt.Errorf("tool %q failed: %w", tool, runErr)
	}

	return stdout, stderr, nil
}

// Available reports whether the named tool can be found in PATH.
func (r *Runner) Available(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// RunPython executes a Python script using python3.
// pythonPath is the python3 interpreter path (or just "python3" to use PATH).
// script is the path to the .py file; args are additional arguments passed after it.
func (r *Runner) RunPython(ctx context.Context, pythonPath, script string, args []string) ([]byte, error) {
	allArgs := append([]string{script}, args...)
	return r.Run(ctx, pythonPath, allArgs)
}
