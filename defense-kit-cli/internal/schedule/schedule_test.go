package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GenerateServiceUnit
// ---------------------------------------------------------------------------

func TestGenerateServiceUnit(t *testing.T) {
	binaryPath := "/usr/local/bin/defense-kit"
	scanMode := "full"

	unit := GenerateServiceUnit(binaryPath, scanMode)

	if !strings.Contains(unit, "ExecStart="+binaryPath) {
		t.Errorf("service unit missing ExecStart with binary path %q; got:\n%s", binaryPath, unit)
	}
	if !strings.Contains(unit, "--"+scanMode) {
		t.Errorf("service unit missing scan mode flag --%s; got:\n%s", scanMode, unit)
	}
	if !strings.Contains(unit, "[Service]") {
		t.Errorf("service unit missing [Service] section; got:\n%s", unit)
	}
	if !strings.Contains(unit, "Type=oneshot") {
		t.Errorf("service unit missing Type=oneshot; got:\n%s", unit)
	}
}

func TestGenerateServiceUnit_QuickMode(t *testing.T) {
	binaryPath := "/opt/defense-kit/bin/defense-kit"
	scanMode := "quick"

	unit := GenerateServiceUnit(binaryPath, scanMode)

	if !strings.Contains(unit, "ExecStart="+binaryPath) {
		t.Errorf("service unit missing ExecStart with binary path %q; got:\n%s", binaryPath, unit)
	}
	if !strings.Contains(unit, "--"+scanMode) {
		t.Errorf("service unit missing scan mode flag --%s; got:\n%s", scanMode, unit)
	}
}

// ---------------------------------------------------------------------------
// GenerateTimerUnit
// ---------------------------------------------------------------------------

func TestGenerateTimerUnit(t *testing.T) {
	interval := 6 * time.Hour

	unit := GenerateTimerUnit(interval)

	if !strings.Contains(unit, "[Timer]") {
		t.Errorf("timer unit missing [Timer] section; got:\n%s", unit)
	}
	if !strings.Contains(unit, "OnUnitActiveSec=") {
		t.Errorf("timer unit missing OnUnitActiveSec; got:\n%s", unit)
	}
	if !strings.Contains(unit, "OnBootSec=5min") {
		t.Errorf("timer unit missing OnBootSec=5min; got:\n%s", unit)
	}
	if !strings.Contains(unit, "[Install]") {
		t.Errorf("timer unit missing [Install] section; got:\n%s", unit)
	}
	if !strings.Contains(unit, "WantedBy=timers.target") {
		t.Errorf("timer unit missing WantedBy=timers.target; got:\n%s", unit)
	}
	// For a 6h interval the value should contain "6h" or equivalent
	if !strings.Contains(unit, "6h") {
		t.Errorf("timer unit OnUnitActiveSec should reflect 6h interval; got:\n%s", unit)
	}
}

func TestGenerateTimerUnit_Minutes(t *testing.T) {
	interval := 30 * time.Minute

	unit := GenerateTimerUnit(interval)

	if !strings.Contains(unit, "30min") {
		t.Errorf("timer unit OnUnitActiveSec should contain 30min; got:\n%s", unit)
	}
}

// ---------------------------------------------------------------------------
// GenerateCronEntry
// ---------------------------------------------------------------------------

func TestGenerateCronEntry(t *testing.T) {
	binaryPath := "/usr/local/bin/defense-kit"
	interval := 6 * time.Hour
	scanMode := "full"

	entry := GenerateCronEntry(binaryPath, interval, scanMode)

	// 6h → every 6 hours: "0 */6 * * *"
	if !strings.Contains(entry, "0 */6 * * *") {
		t.Errorf("cron entry for 6h interval should contain '0 */6 * * *'; got: %s", entry)
	}
	if !strings.Contains(entry, binaryPath) {
		t.Errorf("cron entry missing binary path %q; got: %s", binaryPath, entry)
	}
	if !strings.Contains(entry, "--"+scanMode) {
		t.Errorf("cron entry missing scan mode flag --%s; got: %s", scanMode, entry)
	}
	if !strings.Contains(entry, "--diff") {
		t.Errorf("cron entry missing --diff flag; got: %s", entry)
	}
	if !strings.Contains(entry, "--alert") {
		t.Errorf("cron entry missing --alert flag; got: %s", entry)
	}
	if !strings.Contains(entry, "/var/log/defense-kit.log") {
		t.Errorf("cron entry missing log redirect; got: %s", entry)
	}
}

func TestGenerateCronEntry_Minutes(t *testing.T) {
	binaryPath := "/usr/local/bin/defense-kit"
	interval := 30 * time.Minute
	scanMode := "quick"

	entry := GenerateCronEntry(binaryPath, interval, scanMode)

	// 30 minutes → "*/30 * * * *"
	if !strings.Contains(entry, "*/30 * * * *") {
		t.Errorf("cron entry for 30m interval should contain '*/30 * * * *'; got: %s", entry)
	}
	if !strings.Contains(entry, binaryPath) {
		t.Errorf("cron entry missing binary path %q; got: %s", binaryPath, entry)
	}
}

func TestGenerateCronEntry_Days(t *testing.T) {
	binaryPath := "/usr/local/bin/defense-kit"
	interval := 48 * time.Hour // 2 days
	scanMode := "full"

	entry := GenerateCronEntry(binaryPath, interval, scanMode)

	// 48h → 2 days: "0 0 */2 * *"
	if !strings.Contains(entry, "0 0 */2 * *") {
		t.Errorf("cron entry for 48h (2 days) interval should contain '0 0 */2 * *'; got: %s", entry)
	}
}

func TestGenerateCronEntry_24h(t *testing.T) {
	binaryPath := "/usr/local/bin/defense-kit"
	interval := 24 * time.Hour
	scanMode := "full"

	entry := GenerateCronEntry(binaryPath, interval, scanMode)

	// exactly 24h → 1 day: "0 0 */1 * *"
	if !strings.Contains(entry, "0 0 */1 * *") {
		t.Errorf("cron entry for exactly 24h should contain '0 0 */1 * *'; got: %s", entry)
	}
}

// ---------------------------------------------------------------------------
// DetectBackend
// ---------------------------------------------------------------------------

func TestDetectBackend(t *testing.T) {
	backend := DetectBackend()

	if backend != BackendSystemd && backend != BackendCron {
		t.Errorf("DetectBackend returned unknown backend %q; expected %q or %q",
			backend, BackendSystemd, BackendCron)
	}
}

// ---------------------------------------------------------------------------
// GetStatus
// ---------------------------------------------------------------------------

func TestGetStatus_NotEnabled(t *testing.T) {
	// In a clean test environment neither systemd timer nor cron entry
	// for defense-kit should be active, so Enabled must be false.
	status := GetStatus()

	if status.Enabled {
		t.Errorf("expected Enabled=false in clean test environment, got Enabled=true (backend=%s, interval=%s)",
			status.Backend, status.Interval)
	}
}

// ---------------------------------------------------------------------------
// TestGetStatus_ReturnsStruct — returned value is always a valid Status struct
// ---------------------------------------------------------------------------

func TestGetStatus_ReturnsStruct(t *testing.T) {
	status := GetStatus()

	// Backend must be one of the recognised values or empty string (disabled).
	if status.Enabled {
		if status.Backend != BackendSystemd && status.Backend != BackendCron {
			t.Errorf("GetStatus returned unknown Backend %q when enabled", status.Backend)
		}
		if status.Interval == "" {
			t.Error("GetStatus returned empty Interval when Enabled=true")
		}
	} else {
		// When not enabled Backend and Interval may be empty — that's fine.
		_ = status.Backend
		_ = status.Interval
	}
}

// ---------------------------------------------------------------------------
// TestDetectBackend_ReturnsValid — DetectBackend always returns a known backend
// ---------------------------------------------------------------------------

func TestDetectBackend_ReturnsValid(t *testing.T) {
	backend := DetectBackend()
	if backend != BackendSystemd && backend != BackendCron {
		t.Errorf("DetectBackend returned unexpected value %q", backend)
	}
}

// ---------------------------------------------------------------------------
// TestGenerateServiceUnit_AllModes — quick and full mode variants
// ---------------------------------------------------------------------------

func TestGenerateServiceUnit_AllModes(t *testing.T) {
	binaryPath := "/usr/bin/defense-kit"
	modes := []string{"quick", "full"}

	for _, mode := range modes {
		unit := GenerateServiceUnit(binaryPath, mode)

		if !strings.Contains(unit, "[Unit]") {
			t.Errorf("mode=%s: service unit missing [Unit] section", mode)
		}
		if !strings.Contains(unit, "[Service]") {
			t.Errorf("mode=%s: service unit missing [Service] section", mode)
		}
		if !strings.Contains(unit, "Type=oneshot") {
			t.Errorf("mode=%s: service unit missing Type=oneshot", mode)
		}
		if !strings.Contains(unit, "ExecStart="+binaryPath) {
			t.Errorf("mode=%s: service unit missing ExecStart with binary path", mode)
		}
		if !strings.Contains(unit, "--"+mode) {
			t.Errorf("mode=%s: service unit missing scan mode flag --%s", mode, mode)
		}
		if !strings.Contains(unit, "--diff") {
			t.Errorf("mode=%s: service unit missing --diff flag", mode)
		}
		if !strings.Contains(unit, "--alert") {
			t.Errorf("mode=%s: service unit missing --alert flag", mode)
		}
	}
}

// ---------------------------------------------------------------------------
// TestGenerateTimerUnit_VariousIntervals — 15m, 1h, 6h, 24h, 48h
// ---------------------------------------------------------------------------

func TestGenerateTimerUnit_VariousIntervals(t *testing.T) {
	cases := []struct {
		interval time.Duration
		want     string
	}{
		{15 * time.Minute, "15min"},
		{1 * time.Hour, "1h"},
		{6 * time.Hour, "6h"},
		{24 * time.Hour, "24h"},
		{48 * time.Hour, "48h"},
	}

	for _, tc := range cases {
		unit := GenerateTimerUnit(tc.interval)
		if !strings.Contains(unit, tc.want) {
			t.Errorf("interval=%v: expected %q in timer unit, got:\n%s", tc.interval, tc.want, unit)
		}
		if !strings.Contains(unit, "[Timer]") {
			t.Errorf("interval=%v: timer unit missing [Timer] section", tc.interval)
		}
		if !strings.Contains(unit, "OnBootSec=5min") {
			t.Errorf("interval=%v: timer unit missing OnBootSec=5min", tc.interval)
		}
		if !strings.Contains(unit, "WantedBy=timers.target") {
			t.Errorf("interval=%v: timer unit missing WantedBy=timers.target", tc.interval)
		}
	}
}

// ---------------------------------------------------------------------------
// TestGenerateCronEntry_VariousIntervals — 15m, 1h, 6h, 24h, 48h
// ---------------------------------------------------------------------------

func TestGenerateCronEntry_VariousIntervals(t *testing.T) {
	binary := "/usr/local/bin/defense-kit"
	cases := []struct {
		interval time.Duration
		wantSched string
	}{
		{15 * time.Minute, "*/15 * * * *"},
		{1 * time.Hour, "0 */1 * * *"},
		{6 * time.Hour, "0 */6 * * *"},
		{24 * time.Hour, "0 0 */1 * *"},
		{48 * time.Hour, "0 0 */2 * *"},
	}

	for _, tc := range cases {
		entry := GenerateCronEntry(binary, tc.interval, "full")
		if !strings.Contains(entry, tc.wantSched) {
			t.Errorf("interval=%v: expected schedule %q in entry, got: %s", tc.interval, tc.wantSched, entry)
		}
		if !strings.Contains(entry, binary) {
			t.Errorf("interval=%v: entry missing binary path", tc.interval)
		}
		if !strings.Contains(entry, "# defense-kit") {
			t.Errorf("interval=%v: entry missing marker comment", tc.interval)
		}
		if !strings.Contains(entry, "/var/log/defense-kit.log") {
			t.Errorf("interval=%v: entry missing log redirect", tc.interval)
		}
	}
}

// ---------------------------------------------------------------------------
// filterCronLines via package-internal access (white-box tests)
// ---------------------------------------------------------------------------

func TestFilterCronLines_RemovesMarkedLines(t *testing.T) {
	input := "* * * * * /usr/bin/other-job\n*/6 * * * * /usr/local/bin/defense-kit scan --full # defense-kit\n0 * * * * /usr/bin/backup\n"
	result := filterCronLines(input)

	if strings.Contains(result, "defense-kit") {
		t.Errorf("filterCronLines should remove lines containing 'defense-kit', got:\n%s", result)
	}
	if !strings.Contains(result, "/usr/bin/other-job") {
		t.Errorf("filterCronLines should preserve other cron jobs, got:\n%s", result)
	}
	if !strings.Contains(result, "/usr/bin/backup") {
		t.Errorf("filterCronLines should preserve backup job, got:\n%s", result)
	}
}

func TestFilterCronLines_EmptyInput(t *testing.T) {
	result := filterCronLines("")
	if result != "" {
		t.Errorf("filterCronLines(\"\") should return empty string, got %q", result)
	}
}

func TestFilterCronLines_AllDefenseKit(t *testing.T) {
	input := "*/6 * * * * /usr/local/bin/defense-kit scan --full # defense-kit\n"
	result := filterCronLines(input)
	if result != "" {
		t.Errorf("filterCronLines with only defense-kit lines should return empty string, got %q", result)
	}
}

func TestFilterCronLines_NoDefenseKitLines(t *testing.T) {
	input := "0 * * * * /usr/bin/backup\n30 4 * * * /usr/bin/cleanup\n"
	result := filterCronLines(input)
	if !strings.Contains(result, "/usr/bin/backup") {
		t.Errorf("filterCronLines without defense-kit lines should preserve all content, got:\n%s", result)
	}
	if !strings.Contains(result, "/usr/bin/cleanup") {
		t.Errorf("filterCronLines without defense-kit lines should preserve all content, got:\n%s", result)
	}
}

// ---------------------------------------------------------------------------
// formatSystemdInterval (white-box)
// ---------------------------------------------------------------------------

func TestFormatSystemdInterval_Minutes(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Minute, "5min"},
		{15 * time.Minute, "15min"},
		{30 * time.Minute, "30min"},
		{59 * time.Minute, "59min"},
	}
	for _, tc := range cases {
		got := formatSystemdInterval(tc.d)
		if got != tc.want {
			t.Errorf("formatSystemdInterval(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatSystemdInterval_Hours(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{1 * time.Hour, "1h"},
		{6 * time.Hour, "6h"},
		{24 * time.Hour, "24h"},
		{48 * time.Hour, "48h"},
	}
	for _, tc := range cases {
		got := formatSystemdInterval(tc.d)
		if got != tc.want {
			t.Errorf("formatSystemdInterval(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// intervalToCron (white-box)
// ---------------------------------------------------------------------------

func TestIntervalToCron_Minutes(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Minute, "*/5 * * * *"},
		{15 * time.Minute, "*/15 * * * *"},
		{30 * time.Minute, "*/30 * * * *"},
	}
	for _, tc := range cases {
		got := intervalToCron(tc.d)
		if got != tc.want {
			t.Errorf("intervalToCron(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestIntervalToCron_Hours(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{1 * time.Hour, "0 */1 * * *"},
		{6 * time.Hour, "0 */6 * * *"},
		{12 * time.Hour, "0 */12 * * *"},
	}
	for _, tc := range cases {
		got := intervalToCron(tc.d)
		if got != tc.want {
			t.Errorf("intervalToCron(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestIntervalToCron_Days(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{24 * time.Hour, "0 0 */1 * *"},
		{48 * time.Hour, "0 0 */2 * *"},
		{72 * time.Hour, "0 0 */3 * *"},
	}
	for _, tc := range cases {
		got := intervalToCron(tc.d)
		if got != tc.want {
			t.Errorf("intervalToCron(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers for fake-binary tests
// ---------------------------------------------------------------------------

// writeFakeBinary writes a shell script at dir/name that exits 0 and,
// optionally, prints stdout output.
func writeFakeBinary(t *testing.T, dir, name, script string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := fmt.Sprintf("#!/bin/sh\n%s\n", script)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writeFakeBinary %s: %v", name, err)
	}
}

// prependPath prepends dir to PATH for the duration of the test.
func prependPath(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(filepath.ListSeparator)+orig)
}

// ---------------------------------------------------------------------------
// Enable / Disable via fake crontab binary
//
// Strategy: the fake "crontab" script uses /usr/bin/cat explicitly so that
// it works even when PATH is restricted to the temp directory.
// ---------------------------------------------------------------------------

// makeFakeCrontab writes a fake crontab script that persists crontab state in
// cronStateFile. "-l" prints it; "-" reads stdin and overwrites the file.
// The script uses absolute paths (/usr/bin/cat) so it works with any PATH.
func makeFakeCrontab(t *testing.T, dir, stateFile string) {
	t.Helper()
	script := fmt.Sprintf(
		"#!/bin/sh\nif [ \"$1\" = \"-l\" ]; then\n  /usr/bin/cat \"%s\" 2>/dev/null; exit 0\nelif [ \"$1\" = \"-\" ]; then\n  /usr/bin/cat > \"%s\"; exit 0\nfi\nexit 0\n",
		stateFile, stateFile,
	)
	p := filepath.Join(dir, "crontab")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("makeFakeCrontab: %v", err)
	}
}

// TestEnable_CronBackend verifies that enableCron writes a defense-kit cron
// entry when there is no existing crontab.
func TestEnable_CronBackend(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "crontab.state")
	// No initial content — fake crontab -l returns empty (exit 0).
	makeFakeCrontab(t, tmpDir, stateFile)
	prependPath(t, tmpDir)

	cfg := Config{
		Interval:   6 * time.Hour,
		ScanMode:   "full",
		Backend:    BackendCron,
		BinaryPath: "/usr/local/bin/defense-kit",
	}

	if err := enableCron(cfg); err != nil {
		t.Fatalf("enableCron returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	written := string(data)
	if !strings.Contains(written, "defense-kit") {
		t.Errorf("written crontab should contain 'defense-kit', got:\n%s", written)
	}
	if !strings.Contains(written, "0 */6 * * *") {
		t.Errorf("written crontab should contain 6h schedule, got:\n%s", written)
	}
}

// TestDisable_CronBackend verifies that disableCron removes defense-kit entries
// while preserving unrelated cron jobs.
func TestDisable_CronBackend(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "crontab.state")

	initial := "*/5 * * * * /usr/bin/other-job\n0 */6 * * * /usr/local/bin/defense-kit scan --full --diff --alert >> /var/log/defense-kit.log 2>&1 # defense-kit\n"
	if err := os.WriteFile(stateFile, []byte(initial), 0o644); err != nil {
		t.Fatalf("setup state file: %v", err)
	}

	makeFakeCrontab(t, tmpDir, stateFile)
	prependPath(t, tmpDir)

	if err := disableCron(); err != nil {
		t.Fatalf("disableCron returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	remaining := string(data)
	if strings.Contains(remaining, "defense-kit") {
		t.Errorf("disableCron should have removed defense-kit entry, got:\n%s", remaining)
	}
	if !strings.Contains(remaining, "/usr/bin/other-job") {
		t.Errorf("disableCron should have preserved other cron jobs, got:\n%s", remaining)
	}
}

// TestEnable_CronBackend_WithExistingEntries verifies that enableCron replaces
// an existing defense-kit cron entry rather than appending a duplicate.
func TestEnable_CronBackend_WithExistingEntries(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "crontab.state")

	initial := "*/5 * * * * /usr/bin/backup\n0 */1 * * * /usr/local/bin/defense-kit scan --quick --diff --alert >> /var/log/defense-kit.log 2>&1 # defense-kit\n"
	if err := os.WriteFile(stateFile, []byte(initial), 0o644); err != nil {
		t.Fatalf("setup state file: %v", err)
	}

	makeFakeCrontab(t, tmpDir, stateFile)
	prependPath(t, tmpDir)

	cfg := Config{
		Interval:   6 * time.Hour,
		ScanMode:   "full",
		Backend:    BackendCron,
		BinaryPath: "/usr/local/bin/defense-kit",
	}

	if err := enableCron(cfg); err != nil {
		t.Fatalf("enableCron returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	written := string(data)

	count := strings.Count(written, "# defense-kit")
	if count != 1 {
		t.Errorf("expected exactly 1 defense-kit entry, got %d:\n%s", count, written)
	}
	if !strings.Contains(written, "0 */6 * * *") {
		t.Errorf("expected new 6h schedule in crontab, got:\n%s", written)
	}
	if !strings.Contains(written, "/usr/bin/backup") {
		t.Errorf("expected backup job preserved in crontab, got:\n%s", written)
	}
}

// TestRunCmd_Success verifies runCmd succeeds for a command that exits 0.
func TestRunCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()
	writeFakeBinary(t, tmpDir, "fake-success", `exit 0`)
	prependPath(t, tmpDir)

	if err := runCmd("fake-success"); err != nil {
		t.Errorf("runCmd exiting 0 should not return error, got: %v", err)
	}
}

// TestRunCmd_Failure verifies runCmd returns an error when the command exits non-zero.
func TestRunCmd_Failure(t *testing.T) {
	tmpDir := t.TempDir()
	writeFakeBinary(t, tmpDir, "fake-failure", `exit 1`)
	prependPath(t, tmpDir)

	if err := runCmd("fake-failure"); err == nil {
		t.Error("runCmd exiting 1 should return an error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Enable / Disable public wrappers
// ---------------------------------------------------------------------------

// TestEnable_CronBackend_PublicWrapper verifies the public Enable function
// dispatches to the cron path when Backend=BackendCron.
func TestEnable_CronBackend_PublicWrapper(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "crontab.state")
	makeFakeCrontab(t, tmpDir, stateFile)
	prependPath(t, tmpDir)

	cfg := Config{
		Interval:   1 * time.Hour,
		ScanMode:   "quick",
		Backend:    BackendCron,
		BinaryPath: "/usr/local/bin/defense-kit",
	}

	if err := Enable(cfg); err != nil {
		t.Fatalf("Enable(cron) returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	if !strings.Contains(string(data), "defense-kit") {
		t.Errorf("Enable(cron) did not write cron entry, got:\n%s", string(data))
	}
}

// ---------------------------------------------------------------------------
// systemdTimerInterval — unit parses systemctl show output
// ---------------------------------------------------------------------------

// TestSystemdTimerInterval_ParsesOutput verifies that systemdTimerInterval
// extracts the interval value from fake systemctl output.
func TestSystemdTimerInterval_ParsesOutput(t *testing.T) {
	tmpDir := t.TempDir()

	// Fake systemctl that outputs the expected format for "--user show <timer> --property=OnUnitActiveSec"
	// $1=--user $2=show $3=defense-kit.timer $4=--property=OnUnitActiveSec
	writeFakeBinary(t, tmpDir, "systemctl", `/usr/bin/echo "OnUnitActiveSec=6h"
exit 0
`)
	prependPath(t, tmpDir)

	interval := systemdTimerInterval()
	if interval != "6h" {
		t.Errorf("systemdTimerInterval = %q, want %q", interval, "6h")
	}
}

// ---------------------------------------------------------------------------
// enableSystemd / disableSystemd via fake systemctl
// ---------------------------------------------------------------------------

// TestEnableSystemd verifies that enableSystemd calls daemon-reload and
// enable --now using a fake systemctl binary.
func TestEnableSystemd(t *testing.T) {
	tmpDir := t.TempDir()

	// Fake systemctl: record calls, always exit 0.
	logFile := filepath.Join(tmpDir, "systemctl.log")
	writeFakeBinary(t, tmpDir, "systemctl", fmt.Sprintf(`
/usr/bin/echo "$*" >> "%s"
exit 0
`, logFile))

	prependPath(t, tmpDir)

	// Point HOME to tmpDir so the systemd user dir is created there.
	t.Setenv("HOME", tmpDir)

	cfg := Config{
		Interval:   6 * time.Hour,
		ScanMode:   "full",
		Backend:    BackendSystemd,
		BinaryPath: "/usr/local/bin/defense-kit",
	}

	if err := enableSystemd(cfg); err != nil {
		t.Fatalf("enableSystemd returned unexpected error: %v", err)
	}

	// Verify the unit files were written.
	userDir := filepath.Join(tmpDir, ".config", "systemd", "user")
	if _, err := os.Stat(filepath.Join(userDir, serviceUnitName)); err != nil {
		t.Errorf("service unit file not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(userDir, timerUnitName)); err != nil {
		t.Errorf("timer unit file not created: %v", err)
	}

	// Verify systemctl was called with daemon-reload and enable --now.
	log, _ := os.ReadFile(logFile)
	logStr := string(log)
	if !strings.Contains(logStr, "daemon-reload") {
		t.Errorf("expected daemon-reload call in systemctl log, got:\n%s", logStr)
	}
	if !strings.Contains(logStr, "enable") {
		t.Errorf("expected enable call in systemctl log, got:\n%s", logStr)
	}
}

// TestDisableSystemd verifies that disableSystemd calls systemctl disable and
// removes unit files.
func TestDisableSystemd(t *testing.T) {
	tmpDir := t.TempDir()

	logFile := filepath.Join(tmpDir, "systemctl.log")
	writeFakeBinary(t, tmpDir, "systemctl", fmt.Sprintf(`
/usr/bin/echo "$*" >> "%s"
exit 0
`, logFile))

	prependPath(t, tmpDir)
	t.Setenv("HOME", tmpDir)

	// Pre-create unit files so we can verify they get removed.
	userDir := filepath.Join(tmpDir, ".config", "systemd", "user")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	os.WriteFile(filepath.Join(userDir, serviceUnitName), []byte("[Unit]"), 0o644)
	os.WriteFile(filepath.Join(userDir, timerUnitName), []byte("[Unit]"), 0o644)

	if err := disableSystemd(); err != nil {
		t.Fatalf("disableSystemd returned unexpected error: %v", err)
	}

	// Unit files should be gone.
	if _, err := os.Stat(filepath.Join(userDir, serviceUnitName)); !os.IsNotExist(err) {
		t.Errorf("service unit file should have been removed")
	}
	if _, err := os.Stat(filepath.Join(userDir, timerUnitName)); !os.IsNotExist(err) {
		t.Errorf("timer unit file should have been removed")
	}
}

// ---------------------------------------------------------------------------
// GetStatus with a live cron entry
// ---------------------------------------------------------------------------

// TestGetStatus_CronEnabled verifies GetStatus returns Enabled=true when a
// defense-kit entry is present in the crontab via a fake crontab binary.
func TestGetStatus_CronEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "crontab.state")

	// Pre-populate with a defense-kit cron entry.
	existing := "0 */6 * * * /usr/local/bin/defense-kit scan --full --diff --alert >> /var/log/defense-kit.log 2>&1 # defense-kit\n"
	os.WriteFile(stateFile, []byte(existing), 0o644)
	makeFakeCrontab(t, tmpDir, stateFile)

	// Ensure systemctl is not found so we reach the cron check.
	// Replace PATH entirely — use absolute paths in fake scripts so the shell
	// still works, but systemctl is not on PATH.
	t.Setenv("PATH", tmpDir+":/usr/bin:/bin")

	// Add a dummy systemctl that exits non-zero for is-active queries.
	writeFakeBinary(t, tmpDir, "systemctl", `exit 1`)

	status := GetStatus()
	if !status.Enabled {
		t.Errorf("expected Enabled=true when cron entry exists, got Enabled=false")
	}
	if status.Backend != BackendCron {
		t.Errorf("expected Backend=cron, got %q", status.Backend)
	}
	if !strings.Contains(status.Interval, "defense-kit") {
		t.Errorf("expected Interval to contain the cron line, got %q", status.Interval)
	}
}
