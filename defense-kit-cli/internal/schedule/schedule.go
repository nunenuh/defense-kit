package schedule

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Backend identifies the scheduling mechanism in use.
type Backend string

const (
	BackendSystemd Backend = "systemd"
	BackendCron    Backend = "cron"

	serviceUnitName = "defense-kit.service"
	timerUnitName   = "defense-kit.timer"
	logFile         = "/var/log/defense-kit.log"
	markerComment   = "# defense-kit"
)

// Config holds the parameters needed to enable scheduled scanning.
type Config struct {
	Interval   time.Duration
	ScanMode   string  // "quick" or "full"
	Backend    Backend
	BinaryPath string // path to the defense-kit binary
}

// Status describes the current scheduling state.
type Status struct {
	Enabled  bool
	Backend  Backend
	Interval string
}

// ---------------------------------------------------------------------------
// Backend detection
// ---------------------------------------------------------------------------

// DetectBackend returns BackendSystemd when systemctl is available in PATH,
// otherwise BackendCron.
func DetectBackend() Backend {
	if _, err := exec.LookPath("systemctl"); err == nil {
		return BackendSystemd
	}
	return BackendCron
}

// ---------------------------------------------------------------------------
// Unit / entry generators (exported for testing)
// ---------------------------------------------------------------------------

// GenerateServiceUnit returns the content of a systemd oneshot service unit
// that runs the defense-kit binary in the given scan mode.
func GenerateServiceUnit(binaryPath, scanMode string) string {
	return fmt.Sprintf(`[Unit]
Description=Defense-Kit Security Scan

[Service]
Type=oneshot
ExecStart=%s scan --%s --diff --alert
`, binaryPath, scanMode)
}

// GenerateTimerUnit returns the content of a systemd timer unit that fires
// at the requested interval after boot and then repeatedly.
func GenerateTimerUnit(interval time.Duration) string {
	return fmt.Sprintf(`[Unit]
Description=Defense-Kit Scheduled Scan

[Timer]
OnBootSec=5min
OnUnitActiveSec=%s

[Install]
WantedBy=timers.target
`, formatSystemdInterval(interval))
}

// GenerateCronEntry returns a single crontab line for the given binary,
// interval, and scan mode.
func GenerateCronEntry(binaryPath string, interval time.Duration, scanMode string) string {
	schedule := intervalToCron(interval)
	return fmt.Sprintf("%s %s scan --%s --diff --alert >> %s 2>&1 %s",
		schedule, binaryPath, scanMode, logFile, markerComment)
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

// Enable installs the appropriate scheduler entry for the given config.
func Enable(cfg Config) error {
	switch cfg.Backend {
	case BackendSystemd:
		return enableSystemd(cfg)
	default:
		return enableCron(cfg)
	}
}

// Disable removes all defense-kit scheduling entries.
func Disable() error {
	backend := DetectBackend()
	switch backend {
	case BackendSystemd:
		return disableSystemd()
	default:
		return disableCron()
	}
}

// GetStatus reports whether defense-kit is currently scheduled and via which
// backend.
func GetStatus() Status {
	// Check systemd timer first.
	if isSystemdTimerActive() {
		return Status{
			Enabled:  true,
			Backend:  BackendSystemd,
			Interval: systemdTimerInterval(),
		}
	}

	// Check crontab.
	if entry, ok := findCronEntry(); ok {
		return Status{
			Enabled:  true,
			Backend:  BackendCron,
			Interval: entry,
		}
	}

	return Status{Enabled: false}
}

// ---------------------------------------------------------------------------
// Systemd helpers
// ---------------------------------------------------------------------------

func enableSystemd(cfg Config) error {
	userDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return fmt.Errorf("creating systemd user directory: %w", err)
	}

	servicePath := filepath.Join(userDir, serviceUnitName)
	if err := os.WriteFile(servicePath, []byte(GenerateServiceUnit(cfg.BinaryPath, cfg.ScanMode)), 0o644); err != nil {
		return fmt.Errorf("writing service unit: %w", err)
	}

	timerPath := filepath.Join(userDir, timerUnitName)
	if err := os.WriteFile(timerPath, []byte(GenerateTimerUnit(cfg.Interval)), 0o644); err != nil {
		return fmt.Errorf("writing timer unit: %w", err)
	}

	if err := runCmd("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := runCmd("systemctl", "--user", "enable", "--now", timerUnitName); err != nil {
		return fmt.Errorf("enabling timer: %w", err)
	}
	return nil
}

func disableSystemd() error {
	_ = runCmd("systemctl", "--user", "disable", "--now", timerUnitName)

	userDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	_ = os.Remove(filepath.Join(userDir, timerUnitName))
	_ = os.Remove(filepath.Join(userDir, serviceUnitName))
	return nil
}

func isSystemdTimerActive() bool {
	// A non-zero exit code means the timer is not loaded/active.
	cmd := exec.Command("systemctl", "--user", "is-active", "--quiet", timerUnitName)
	return cmd.Run() == nil
}

func systemdTimerInterval() string {
	out, err := exec.Command("systemctl", "--user", "show", timerUnitName, "--property=OnUnitActiveSec").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	// output is "OnUnitActiveSec=6h" — strip the key
	parts := strings.SplitN(line, "=", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return line
}

// ---------------------------------------------------------------------------
// Cron helpers
// ---------------------------------------------------------------------------

func enableCron(cfg Config) error {
	current, err := getCrontab()
	if err != nil {
		// crontab -l exits non-zero when there is no crontab yet — treat as empty.
		current = ""
	}

	cleaned := filterCronLines(current)
	entry := GenerateCronEntry(cfg.BinaryPath, cfg.Interval, cfg.ScanMode)

	var sb strings.Builder
	if cleaned != "" {
		sb.WriteString(cleaned)
		if !strings.HasSuffix(cleaned, "\n") {
			sb.WriteByte('\n')
		}
	}
	sb.WriteString(entry)
	sb.WriteByte('\n')

	return setCrontab(sb.String())
}

func disableCron() error {
	current, err := getCrontab()
	if err != nil {
		return nil // nothing to remove
	}
	cleaned := filterCronLines(current)
	return setCrontab(cleaned)
}

func getCrontab() (string, error) {
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func setCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing crontab: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// filterCronLines removes all lines that contain the defense-kit marker.
func filterCronLines(crontab string) string {
	lines := strings.Split(crontab, "\n")
	var kept []string
	for _, line := range lines {
		if !strings.Contains(line, "defense-kit") {
			kept = append(kept, line)
		}
	}
	result := strings.Join(kept, "\n")
	// Trim trailing newlines then add exactly one.
	result = strings.TrimRight(result, "\n")
	if result == "" {
		return ""
	}
	return result + "\n"
}

func findCronEntry() (string, bool) {
	current, err := getCrontab()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(current, "\n") {
		if strings.Contains(line, "defense-kit") {
			return line, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// formatSystemdInterval converts a duration to a systemd time span string.
// systemd accepts "Xmin", "Xh", etc.
func formatSystemdInterval(d time.Duration) string {
	total := d.Round(time.Second)
	if total < time.Hour {
		mins := int(total.Minutes())
		return fmt.Sprintf("%dmin", mins)
	}
	hours := int(total.Hours())
	return fmt.Sprintf("%dh", hours)
}

// intervalToCron converts a duration to a cron schedule expression.
//
//	< 1 hour  → */N * * * *       (every N minutes)
//	< 24 hour → 0 */N * * *       (every N hours)
//	>= 24h    → 0 0 */N * *       (every N days)
func intervalToCron(d time.Duration) string {
	minutes := int(d.Minutes())
	hours := int(d.Hours())
	days := hours / 24

	switch {
	case days >= 1:
		return fmt.Sprintf("0 0 */%d * *", days)
	case hours >= 1:
		return fmt.Sprintf("0 */%d * * *", hours)
	default:
		return fmt.Sprintf("*/%d * * * *", minutes)
	}
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
