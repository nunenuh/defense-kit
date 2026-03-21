package schedule

import (
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
