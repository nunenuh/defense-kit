package system

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// MACScanner checks whether a Mandatory Access Control (MAC) framework —
// AppArmor or SELinux — is active and enforcing.
type MACScanner struct {
	appArmorPath string
	selinuxPath  string
}

// NewMACScanner creates a MACScanner with production defaults.
func NewMACScanner() *MACScanner {
	return &MACScanner{
		appArmorPath: "/sys/module/apparmor/parameters/enabled",
		selinuxPath:  "/sys/fs/selinux/enforce",
	}
}

// NewMACScannerWithPaths creates a MACScanner with custom paths (used in
// tests).
func NewMACScannerWithPaths(appArmorPath, selinuxPath string) *MACScanner {
	return &MACScanner{
		appArmorPath: appArmorPath,
		selinuxPath:  selinuxPath,
	}
}

func (s *MACScanner) Name() string            { return "mac" }
func (s *MACScanner) Category() string        { return "system" }
func (s *MACScanner) RequiresRoot() bool      { return false }
func (s *MACScanner) RequiredTools() []string { return nil }
func (s *MACScanner) OptionalTools() []string { return nil }
func (s *MACScanner) Available() bool         { return true }
func (s *MACScanner) Description() string {
	return "Checks whether a Mandatory Access Control framework (AppArmor or SELinux) is active and in enforcing mode."
}

// Scan checks AppArmor and SELinux status and returns findings for missing or
// non-enforcing MAC configurations.
func (s *MACScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	appArmorEnabled, appArmorComplain := s.checkAppArmor()
	selinuxEnforcing, selinuxPermissive := s.checkSELinux()

	var findings []scanner.Finding

	// Neither MAC system is present → MEDIUM.
	if !appArmorEnabled && !selinuxEnforcing && !selinuxPermissive {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), "/sys", "no mandatory access control"),
			Scanner:  s.Name(),
			Severity: scanner.SevMedium,
			Title:    "No mandatory access control system is enabled",
			Detail:   "Neither AppArmor nor SELinux is active on this system. MAC frameworks provide an additional layer of defense that confines processes and limits the impact of vulnerabilities.",
			Evidence: fmt.Sprintf(
				"AppArmor path: %s (not found or disabled), SELinux path: %s (not found)",
				s.appArmorPath, s.selinuxPath,
			),
			Location:    "/sys",
			Remediation: "Install and enable AppArmor (default on Ubuntu/Debian) or SELinux (default on RHEL/CentOS). Ensure profiles are in enforcing mode.",
			References: []string{
				"https://www.cisecurity.org/benchmark/ubuntu_linux",
				"https://wiki.ubuntu.com/AppArmor",
			},
		})
		return findings, nil
	}

	// AppArmor is loaded but in complain mode → LOW.
	if appArmorComplain {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), s.appArmorPath, "apparmor complain mode"),
			Scanner:  s.Name(),
			Severity: scanner.SevLow,
			Title:    "AppArmor is in complain mode (not enforcing)",
			Detail:   "AppArmor is loaded but operating in complain mode. In complain mode, policy violations are logged but not blocked, providing no real access control enforcement.",
			Evidence: fmt.Sprintf("AppArmor enabled path: %s", s.appArmorPath),
			Location: s.appArmorPath,
			Remediation: "Switch AppArmor profiles to enforce mode: run 'aa-enforce /etc/apparmor.d/*' and ensure no profiles are in complain mode.",
			References: []string{
				"https://gitlab.com/apparmor/apparmor/-/wikis/Documentation",
			},
		})
	}

	// SELinux is loaded but in permissive mode → LOW.
	if selinuxPermissive && !selinuxEnforcing {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), s.selinuxPath, "selinux permissive mode"),
			Scanner:  s.Name(),
			Severity: scanner.SevLow,
			Title:    "SELinux is in permissive mode (not enforcing)",
			Detail:   "SELinux is loaded but operating in permissive mode. In permissive mode, policy violations are logged but not enforced, providing no real mandatory access control.",
			Evidence: fmt.Sprintf("SELinux enforce path: %s (value: 0)", s.selinuxPath),
			Location: s.selinuxPath,
			Remediation: "Switch SELinux to enforcing mode: run 'setenforce 1' and set SELINUX=enforcing in /etc/selinux/config.",
			References: []string{
				"https://selinuxproject.org/page/Guide",
			},
		})
	}

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkAppArmor returns (enabled, complainMode).
// enabled is true when AppArmor is loaded (enabled file reads "Y").
// complainMode is true when AppArmor is loaded but no profile is in enforce
// mode (we approximate this by checking if the module is loaded but no
// enforce-mode indicator is present — in practice, we flag complain mode
// only when the enabled file says "Y" but /sys/kernel/security/apparmor/profiles
// is absent, since that requires root to enumerate precisely).
func (s *MACScanner) checkAppArmor() (enabled, complainMode bool) {
	data, err := os.ReadFile(s.appArmorPath)
	if err != nil {
		return false, false
	}
	value := strings.TrimSpace(string(data))
	if strings.EqualFold(value, "Y") || value == "1" {
		// AppArmor module is loaded. Check for complain-mode indicator.
		// The /sys/kernel/security/apparmor/profiles file lists all loaded
		// profiles with their mode. If it is readable and contains only
		// "complain" entries, AppArmor is not enforcing anything.
		profilesPath := "/sys/kernel/security/apparmor/profiles"
		profileData, profileErr := os.ReadFile(profilesPath)
		if profileErr == nil {
			content := string(profileData)
			if strings.Contains(content, "(enforce)") {
				return true, false // at least one profile in enforce mode
			}
			if strings.Contains(content, "(complain)") {
				return true, true // profiles loaded but all in complain mode
			}
		}
		// Cannot determine enforce vs. complain — assume enforcing to avoid
		// false positives on systems where the profiles file is unreadable.
		return true, false
	}
	return false, false
}

// checkSELinux returns (enforcing, permissive).
// enforcing is true when /sys/fs/selinux/enforce reads "1".
// permissive is true when the file exists but reads "0".
func (s *MACScanner) checkSELinux() (enforcing, permissive bool) {
	data, err := os.ReadFile(s.selinuxPath)
	if err != nil {
		return false, false
	}
	value := strings.TrimSpace(string(data))
	if value == "1" {
		return true, false
	}
	if value == "0" {
		return false, true
	}
	return false, false
}
