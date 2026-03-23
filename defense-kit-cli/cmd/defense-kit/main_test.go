package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles the defense-kit binary into a temporary directory and
// returns the path to the resulting executable.
func buildBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binary := filepath.Join(tmpDir, "defense-kit")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "." // run from cmd/defense-kit
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return binary
}

// TestCLI_ScanHelp verifies that `defense-kit scan --help` exits cleanly and
// documents the expected flags.
func TestCLI_ScanHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "scan", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("scan --help exited with error: %v\noutput:\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{"--quick", "--category"} {
		if !strings.Contains(output, want) {
			t.Errorf("scan --help: missing expected flag %q\nfull output:\n%s", want, output)
		}
	}
}

// TestCLI_ToolsCheck verifies that `defense-kit tools check` exits cleanly and
// prints the expected scanner count summary line.
func TestCLI_ToolsCheck(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "tools", "check").CombinedOutput()
	if err != nil {
		t.Fatalf("tools check exited with error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "scanners available") {
		t.Errorf("tools check: missing 'scanners available' summary line\nfull output:\n%s", out)
	}
}

// TestCLI_HardenHelp verifies that `defense-kit harden --help` exits cleanly
// and documents the expected flags.
func TestCLI_HardenHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "harden", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("harden --help exited with error: %v\noutput:\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{"--dry-run", "--mode"} {
		if !strings.Contains(output, want) {
			t.Errorf("harden --help: missing expected flag %q\nfull output:\n%s", want, output)
		}
	}
}

// TestCLI_ScheduleStatus verifies that `defense-kit schedule status` exits
// cleanly and prints a meaningful status line.
func TestCLI_ScheduleStatus(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "schedule", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("schedule status exited with error: %v\noutput:\n%s", err, out)
	}
	// When no schedule is configured the command should say "disabled".
	if !strings.Contains(string(out), "Scheduled scanning") {
		t.Errorf("schedule status: expected 'Scheduled scanning' in output\nfull output:\n%s", out)
	}
}

// TestCLI_DashboardHelp verifies that `defense-kit dashboard --help` exits
// cleanly and documents the expected flags.
func TestCLI_DashboardHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "dashboard", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard --help exited with error: %v\noutput:\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{"--port", "--open"} {
		if !strings.Contains(output, want) {
			t.Errorf("dashboard --help: missing expected flag %q\nfull output:\n%s", want, output)
		}
	}
}

// TestCLI_ComplyHelp verifies that `defense-kit comply --help` exits cleanly
// and documents the expected flags.
func TestCLI_ComplyHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "comply", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("comply --help exited with error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "--framework") {
		t.Errorf("comply --help: missing '--framework' flag\nfull output:\n%s", out)
	}
}

// TestCLI_BaselineHelp verifies that `defense-kit baseline --help` exits
// cleanly and lists the expected sub-commands.
func TestCLI_BaselineHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "baseline", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("baseline --help exited with error: %v\noutput:\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{"update", "diff"} {
		if !strings.Contains(output, want) {
			t.Errorf("baseline --help: missing sub-command %q\nfull output:\n%s", want, output)
		}
	}
}

// TestCLI_RootHelp verifies that running the binary with no arguments (or
// --help) exits cleanly and lists the top-level commands.
func TestCLI_RootHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("--help exited with error: %v\noutput:\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{"scan", "harden", "baseline", "tools", "comply", "dashboard"} {
		if !strings.Contains(output, want) {
			t.Errorf("root --help: missing sub-command %q\nfull output:\n%s", want, output)
		}
	}
}
