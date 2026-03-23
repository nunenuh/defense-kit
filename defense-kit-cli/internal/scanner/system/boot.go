package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// BootScanner audits bootloader configuration and secure boot settings.
type BootScanner struct {
	// grubConfigPath is the path to the GRUB config file.
	grubConfigPath string
	// cmdlinePath is the path to /proc/cmdline.
	cmdlinePath string
	// efiVarsDir is the directory containing EFI variables.
	efiVarsDir string
	// bootDir is the directory containing boot files (initramfs etc.).
	bootDir string
}

// NewBootScanner creates a new BootScanner.
func NewBootScanner() *BootScanner {
	return &BootScanner{
		grubConfigPath: "/boot/grub/grub.cfg",
		cmdlinePath:    "/proc/cmdline",
		efiVarsDir:     "/sys/firmware/efi/efivars",
		bootDir:        "/boot",
	}
}

// NewBootScannerWithPaths creates a BootScanner with custom paths (used in
// tests).
func NewBootScannerWithPaths(grubConfig, cmdline, efiVarsDir, bootDir string) *BootScanner {
	return &BootScanner{
		grubConfigPath: grubConfig,
		cmdlinePath:    cmdline,
		efiVarsDir:     efiVarsDir,
		bootDir:        bootDir,
	}
}

func (s *BootScanner) Name() string            { return "boot" }
func (s *BootScanner) Category() string        { return "system" }
func (s *BootScanner) RequiresRoot() bool      { return true }
func (s *BootScanner) RequiredTools() []string { return nil }
func (s *BootScanner) OptionalTools() []string { return nil }
func (s *BootScanner) Available() bool         { return true }
func (s *BootScanner) Description() string {
	return "Audits bootloader configuration (GRUB, systemd-boot) and UEFI Secure Boot status for integrity weaknesses."
}

// Scan audits bootloader configuration and secure boot settings.
func (s *BootScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.checkGrubConfig()...)
	findings = append(findings, s.checkKernelCmdline()...)
	findings = append(findings, s.checkSecureBoot()...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// CheckGrubConfig is exported for testing.
func (s *BootScanner) CheckGrubConfig() []scanner.Finding {
	return s.checkGrubConfig()
}

// CheckKernelCmdline is exported for testing.
func (s *BootScanner) CheckKernelCmdline() []scanner.Finding {
	return s.checkKernelCmdline()
}

// checkGrubConfig checks the GRUB configuration for world-writable permissions.
func (s *BootScanner) checkGrubConfig() []scanner.Finding {
	info, err := os.Stat(s.grubConfigPath)
	if err != nil {
		// GRUB config not found — may be using systemd-boot or another bootloader.
		return nil
	}

	var findings []scanner.Finding
	mode := info.Mode()

	// World-writable GRUB config allows any user to modify boot parameters.
	if mode&0o002 != 0 {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("boot", s.grubConfigPath, "world-writable GRUB config"),
			Scanner:  "boot",
			Severity: scanner.SevHigh,
			Title:    "GRUB configuration file is world-writable",
			Detail: fmt.Sprintf(
				"The GRUB configuration file %q has permissions %s and is world-writable. Any user can modify the bootloader configuration to add malicious kernel parameters or change the boot target.",
				s.grubConfigPath, mode.String(),
			),
			Evidence:    fmt.Sprintf("path: %s, mode: %s", s.grubConfigPath, mode.String()),
			Location:    s.grubConfigPath,
			Remediation: fmt.Sprintf("Run: chmod 600 %s && chown root:root %s", s.grubConfigPath, s.grubConfigPath),
			CanAutoFix:  true,
			References: []string{
				"https://www.cisecurity.org/benchmark/ubuntu_linux",
			},
		})
	}

	// Group-writable GRUB config is also a concern.
	if mode&0o020 != 0 {
		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID("boot", s.grubConfigPath, "group-writable GRUB config"),
			Scanner:  "boot",
			Severity: scanner.SevMedium,
			Title:    "GRUB configuration file is group-writable",
			Detail: fmt.Sprintf(
				"The GRUB configuration file %q has permissions %s and is group-writable. Members of the file's group can modify bootloader configuration.",
				s.grubConfigPath, mode.String(),
			),
			Evidence:    fmt.Sprintf("path: %s, mode: %s", s.grubConfigPath, mode.String()),
			Location:    s.grubConfigPath,
			Remediation: fmt.Sprintf("Run: chmod 600 %s && chown root:root %s", s.grubConfigPath, s.grubConfigPath),
			CanAutoFix:  true,
		})
	}

	return findings
}

// suspiciousKernelParams lists kernel command-line parameters that indicate
// an insecure or attacker-modified boot.
var suspiciousKernelParams = []struct {
	param       string
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}{
	{
		param:       "init=/bin/sh",
		title:       "Kernel booted with init=/bin/sh (single-user shell)",
		severity:    scanner.SevCritical,
		detail:      "The kernel was booted with 'init=/bin/sh', which drops directly into a root shell without authentication. This is a common technique for bypassing authentication on physical access.",
		remediation: "Reboot the system normally. Ensure GRUB has a password set and that physical access is restricted.",
	},
	{
		param:       "init=/bin/bash",
		title:       "Kernel booted with init=/bin/bash (root shell)",
		severity:    scanner.SevCritical,
		detail:      "The kernel was booted with 'init=/bin/bash', which drops directly into a root shell without authentication.",
		remediation: "Reboot the system normally. Ensure GRUB has a password set and that physical access is restricted.",
	},
	{
		param:       "single",
		title:       "Kernel booted in single-user mode",
		severity:    scanner.SevCritical,
		detail:      "The system was booted in single-user mode. Single-user mode typically provides a root shell without requiring authentication.",
		remediation: "Reboot into normal multi-user mode. Ensure GRUB is password-protected to prevent unauthorized single-user boots.",
	},
	{
		param:       "s ",
		title:       "Kernel booted in single-user mode (s flag)",
		severity:    scanner.SevCritical,
		detail:      "The system was booted with the 's' runlevel parameter, indicating single-user mode.",
		remediation: "Reboot into normal multi-user mode and restrict GRUB access.",
	},
	{
		param:       "emergency",
		title:       "Kernel booted in emergency mode",
		severity:    scanner.SevHigh,
		detail:      "The system was booted in emergency mode, which provides a minimal shell with limited authentication. This may have been done to bypass normal security controls.",
		remediation: "Reboot into normal mode and investigate why emergency mode was triggered.",
	},
	{
		param:       "rw init=",
		title:       "Kernel booted with custom init and rw root",
		severity:    scanner.SevCritical,
		detail:      "The kernel was booted with a custom init binary and a writable root filesystem. This combination can be used to modify system files before normal boot.",
		remediation: "Reboot the system normally and audit for unauthorized changes.",
	},
}

// checkKernelCmdline reads /proc/cmdline and checks for suspicious parameters.
func (s *BootScanner) checkKernelCmdline() []scanner.Finding {
	data, err := os.ReadFile(s.cmdlinePath)
	if err != nil {
		return nil
	}
	cmdline := strings.TrimSpace(string(data))

	var findings []scanner.Finding
	for _, p := range suspiciousKernelParams {
		if strings.Contains(cmdline, p.param) {
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("boot", s.cmdlinePath, p.title),
				Scanner:     "boot",
				Severity:    p.severity,
				Title:       p.title,
				Detail:      p.detail,
				Evidence:    cmdline,
				Location:    s.cmdlinePath,
				Remediation: p.remediation,
				References: []string{
					"https://attack.mitre.org/techniques/T1542/",
				},
			})
		}
	}
	return findings
}

// checkSecureBoot checks the UEFI Secure Boot status via EFI variables.
func (s *BootScanner) checkSecureBoot() []scanner.Finding {
	// Check if EFI variables directory exists.
	if _, err := os.Stat(s.efiVarsDir); os.IsNotExist(err) {
		// Non-UEFI system or EFI variables not mounted — skip.
		return nil
	}

	// Look for SecureBoot-* EFI variable files.
	matches, err := filepath.Glob(filepath.Join(s.efiVarsDir, "SecureBoot-*"))
	if err != nil || len(matches) == 0 {
		// Secure Boot variable not found — cannot determine status.
		return nil
	}

	// The SecureBoot EFI variable is a binary blob. The last byte of the
	// data payload (after a 4-byte attribute prefix) indicates the state:
	// 0x00 = disabled, 0x01 = enabled.
	for _, varPath := range matches {
		data, err := os.ReadFile(varPath)
		if err != nil {
			continue
		}
		// The EFI variable has a 4-byte attribute header; the value follows.
		// For SecureBoot, the value is a single byte: 0 = off, 1 = on.
		if len(data) < 5 {
			continue
		}
		secureBootEnabled := data[4] == 0x01

		if !secureBootEnabled {
			return []scanner.Finding{
				{
					ID:       scanner.GenerateFindingID("boot", varPath, "Secure Boot disabled"),
					Scanner:  "boot",
					Severity: scanner.SevLow,
					Title:    "UEFI Secure Boot is disabled",
					Detail:   "Secure Boot is a UEFI feature that prevents unsigned or untrusted bootloaders and kernels from running. When disabled, an attacker with physical access or boot-level access can install malicious bootloaders.",
					Evidence:  fmt.Sprintf("SecureBoot EFI variable: %s, value: 0x%02x", varPath, data[4]),
					Location:  varPath,
					Remediation: "Enable Secure Boot in the UEFI/BIOS firmware settings. Ensure your bootloader and kernel are signed with trusted keys.",
					References: []string{
						"https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot",
					},
				},
			}
		}
		// Secure Boot is enabled — no finding needed.
		return nil
	}

	return nil
}
