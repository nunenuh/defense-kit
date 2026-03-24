package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunnerRun_Echo(t *testing.T) {
	r := NewRunner()
	out, err := r.Run(context.Background(), "echo", []string{"hello", "world"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "hello world" {
		t.Errorf("expected 'hello world', got %q", got)
	}
}

func TestRunnerRun_NonexistentBinary(t *testing.T) {
	r := NewRunner()
	_, err := r.Run(context.Background(), "nonexistent_binary_xyz_123", []string{})
	if err == nil {
		t.Fatal("expected an error for nonexistent binary, got nil")
	}
}

func TestRunnerRun_ContextTimeout(t *testing.T) {
	r := NewRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// sleep is a long-running command that should be cancelled
	_, err := r.Run(ctx, "sleep", []string{"10"})
	if err == nil {
		t.Fatal("expected context deadline/timeout error, got nil")
	}
}

func TestRunnerAvailable_Echo(t *testing.T) {
	r := NewRunner()
	if !r.Available("echo") {
		t.Error("expected 'echo' to be available")
	}
}

func TestRunnerAvailable_Nonexistent(t *testing.T) {
	r := NewRunner()
	if r.Available("nonexistent_xyz_456") {
		t.Error("expected 'nonexistent_xyz_456' to not be available")
	}
}

func TestRunnerRunWithStderr(t *testing.T) {
	r := NewRunner()
	stdout, stderr, err := r.RunWithStderr(context.Background(), "echo", []string{"hello"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	got := strings.TrimSpace(string(stdout))
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
	// stderr should be empty for echo
	_ = stderr
}

func TestRunner_RunWithStderr_CapturesStderr(t *testing.T) {
	// Use sh to write to both stdout and stderr.
	r := NewRunner()
	stdout, stderr, err := r.RunWithStderr(
		context.Background(),
		"sh",
		[]string{"-c", "echo out; echo err >&2"},
	)
	// sh exits 0 so err should be nil.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(stdout)) != "out" {
		t.Errorf("expected stdout='out', got %q", string(stdout))
	}
	if strings.TrimSpace(string(stderr)) != "err" {
		t.Errorf("expected stderr='err', got %q", string(stderr))
	}
}

func TestRunner_RunWithStderr_Nonexistent(t *testing.T) {
	r := NewRunner()
	stdout, stderr, err := r.RunWithStderr(context.Background(), "nonexistent_binary_xyz_789", []string{})
	if err == nil {
		t.Fatal("expected error for nonexistent binary, got nil")
	}
	// stdout and stderr should be nil/empty when the binary is not found.
	_ = stdout
	_ = stderr
}
