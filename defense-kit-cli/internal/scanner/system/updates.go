package system

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const (
	autoUpgradesPath  = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptCachePath      = "/var/cache/apt/pkgcache.bin"
	aptStaleThreshold = 7 * 24 * time.Hour // 7 days
)

// UpdatesScanner checks whether automatic security updates are configured and
// whether the system has pending security patches.
type UpdatesScanner struct {
	autoUpgradesPath string
	aptCachePath     string
}

// NewUpdatesScanner creates an UpdatesScanner with production defaults.
func NewUpdatesScanner() *UpdatesScanner {
	return &UpdatesScanner{
		autoUpgradesPath: autoUpgradesPath,
		aptCachePath:     aptCachePath,
	}
}

// NewUpdatesScannerWithPaths creates an UpdatesScanner with custom paths (used
// in tests).
func NewUpdatesScannerWithPaths(autoUpgradesPath, aptCachePath string) *UpdatesScanner {
	return &UpdatesScanner{
		autoUpgradesPath: autoUpgradesPath,
		aptCachePath:     aptCachePath,
	}
}

func (s *UpdatesScanner) Name() string            { return "updates" }
func (s *UpdatesScanner) Category() string        { return "system" }
func (s *UpdatesScanner) RequiresRoot() bool      { return false }
func (s *UpdatesScanner) RequiredTools() []string { return nil }
func (s *UpdatesScanner) OptionalTools() []string { return []string{"apt"} }
func (s *UpdatesScanner) Available() bool         { return true }
func (s *UpdatesScanner) Description() string {
	return "Checks whether unattended-upgrades is configured, whether the apt package cache is stale, and whether security updates are pending."
}

// Scan performs all update-related checks and returns findings.
func (s *UpdatesScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.checkAutoUpgrades()...)
	findings = append(findings, s.checkAptCacheAge()...)
	findings = append(findings, s.checkPendingSecurityUpdates(ctx, opts)...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkAutoUpgrades checks whether the unattended-upgrades configuration file
// exists and enables automatic security updates.
func (s *UpdatesScanner) checkAutoUpgrades() []scanner.Finding {
	_, err := os.Stat(s.autoUpgradesPath)
	if err == nil {
		// File exists — unattended-upgrades appears to be installed.
		return nil
	}
	if !os.IsNotExist(err) {
		return nil
	}

	return []scanner.Finding{
		{
			ID:       scanner.GenerateFindingID(s.Name(), s.autoUpgradesPath, "auto-upgrades not configured"),
			Scanner:  s.Name(),
			Severity: scanner.SevMedium,
			Title:    "Automatic security updates are not configured",
			Detail:   "The unattended-upgrades configuration file was not found. Without automatic security updates, this system may remain vulnerable to publicly known CVEs until patches are applied manually.",
			Evidence: fmt.Sprintf("file not found: %s", s.autoUpgradesPath),
			Location: s.autoUpgradesPath,
			Remediation: "Install unattended-upgrades: run 'apt install unattended-upgrades' and enable automatic security updates with 'dpkg-reconfigure unattended-upgrades'.",
			References: []string{
				"https://help.ubuntu.com/community/AutomaticSecurityUpdates",
			},
		},
	}
}

// checkAptCacheAge checks how recently the apt package cache was updated.
// A cache older than 7 days suggests the package list has not been refreshed.
func (s *UpdatesScanner) checkAptCacheAge() []scanner.Finding {
	info, err := os.Stat(s.aptCachePath)
	if err != nil {
		// Cache file not present — apt may not be installed or has never run.
		return nil
	}

	age := time.Since(info.ModTime())
	if age <= aptStaleThreshold {
		return nil
	}

	return []scanner.Finding{
		{
			ID:       scanner.GenerateFindingID(s.Name(), s.aptCachePath, "stale apt cache"),
			Scanner:  s.Name(),
			Severity: scanner.SevMedium,
			Title:    fmt.Sprintf("APT package cache is stale (%d days old)", int(age.Hours()/24)),
			Detail: fmt.Sprintf(
				"The APT package cache at %s was last updated %d days ago (threshold: 7 days). A stale cache means the system may not be aware of available security updates.",
				s.aptCachePath, int(age.Hours()/24),
			),
			Evidence:    fmt.Sprintf("apt cache last modified: %s", info.ModTime().Format(time.RFC3339)),
			Location:    s.aptCachePath,
			Remediation: "Update the package cache: run 'apt update' and then 'apt upgrade -y' to apply available updates.",
			References: []string{
				"https://help.ubuntu.com/community/AptGet/Howto",
			},
		},
	}
}

// checkPendingSecurityUpdates runs 'apt list --upgradable' and counts lines
// containing "security". Returns a HIGH finding if any security updates are
// pending.
func (s *UpdatesScanner) checkPendingSecurityUpdates(ctx context.Context, opts scanner.ScanOptions) []scanner.Finding {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("apt") {
		return nil
	}

	out, err := opts.ToolRunner.Run(ctx, "apt", []string{"list", "--upgradable"})
	if err != nil && len(out) == 0 {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	var securityLines []string
	for _, line := range lines {
		if strings.Contains(line, "security") {
			securityLines = append(securityLines, strings.TrimSpace(line))
		}
	}

	if len(securityLines) == 0 {
		return nil
	}

	evidence := strings.Join(securityLines, "\n")
	if len(evidence) > 500 {
		evidence = evidence[:500] + "..."
	}

	return []scanner.Finding{
		{
			ID:       scanner.GenerateFindingID(s.Name(), "apt-upgradable", "pending security updates"),
			Scanner:  s.Name(),
			Severity: scanner.SevHigh,
			Title:    fmt.Sprintf("%d pending security update(s) detected", len(securityLines)),
			Detail: fmt.Sprintf(
				"%d security packages are available for upgrade. Unpatched security vulnerabilities may be exploitable by attackers.",
				len(securityLines),
			),
			Evidence:    evidence,
			Location:    "apt-upgradable",
			Remediation: "Apply security updates immediately: run 'apt update && apt upgrade -y'.",
			References: []string{
				"https://ubuntu.com/security/notices",
			},
		},
	}
}
