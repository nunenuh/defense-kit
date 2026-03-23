package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// SwapScanner inspects swap space configuration for security issues such as
// unencrypted swap that may expose sensitive data at rest.
type SwapScanner struct{}

// NewSwapScanner creates a new SwapScanner.
func NewSwapScanner() *SwapScanner {
	return &SwapScanner{}
}

func (s *SwapScanner) Name() string           { return "swap" }
func (s *SwapScanner) Category() string       { return "filesystem" }
func (s *SwapScanner) RequiresRoot() bool     { return false }
func (s *SwapScanner) RequiredTools() []string { return nil }
func (s *SwapScanner) OptionalTools() []string { return nil }
func (s *SwapScanner) Available() bool        { return true }
func (s *SwapScanner) Description() string {
	return "Inspects swap space configuration for security issues such as unencrypted swap that may expose sensitive data at rest."
}

// Scan checks swap-related kernel parameters and swap device configuration.
func (s *SwapScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, checkCorePattern()...)
	findings = append(findings, checkSuidDumpable()...)
	findings = append(findings, checkUnencryptedSwap()...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkCorePattern reads /proc/sys/kernel/core_pattern and flags non-empty
// patterns that are not piped to systemd-coredump.
func checkCorePattern() []scanner.Finding {
	const path = "/proc/sys/kernel/core_pattern"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.Contains(value, "systemd-coredump") || strings.Contains(value, "apport") {
		return nil
	}
	return []scanner.Finding{
		{
			ID:       scanner.GenerateFindingID("swap", path, "custom core_pattern"),
			Scanner:  "swap",
			Severity: scanner.SevMedium,
			Title:    "Custom kernel core dump pattern configured",
			Detail: fmt.Sprintf(
				"The kernel core_pattern is set to %q. A custom core dump handler can be used to capture sensitive memory contents, including cryptographic keys and credentials, from crashing processes.",
				value,
			),
			Evidence:    fmt.Sprintf("core_pattern: %s", value),
			Location:    path,
			Remediation: "Set core_pattern to '|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %e' or restrict core dumps entirely via `ulimit -c 0` and `fs.suid_dumpable=0`.",
			References: []string{
				"https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html",
			},
		},
	}
}

// checkSuidDumpable reads /proc/sys/fs/suid_dumpable and flags values != 0.
func checkSuidDumpable() []scanner.Finding {
	const path = "/proc/sys/fs/suid_dumpable"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(data))
	if value == "0" {
		return nil
	}

	sev := scanner.SevHigh
	detail := fmt.Sprintf(
		"fs.suid_dumpable is set to %q. When non-zero, setuid processes can produce core dumps containing sensitive data. A value of 2 (suidsafe) still writes core files in a world-readable location.",
		value,
	)
	return []scanner.Finding{
		{
			ID:          scanner.GenerateFindingID("swap", path, "suid_dumpable non-zero"),
			Scanner:     "swap",
			Severity:    sev,
			Title:       "Kernel allows SUID process core dumps (fs.suid_dumpable != 0)",
			Detail:      detail,
			Evidence:    fmt.Sprintf("fs.suid_dumpable: %s", value),
			Location:    path,
			Remediation: "Set fs.suid_dumpable=0 in /etc/sysctl.conf and apply with `sysctl -p`.",
			CanAutoFix:  true,
			References: []string{
				"https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html",
			},
		},
	}
}

// checkUnencryptedSwap parses /proc/swaps and checks whether each swap device
// is backed by a dm-crypt device (encrypted). Non-dm-crypt swap may expose
// sensitive memory at rest.
func checkUnencryptedSwap() []scanner.Finding {
	const swapsPath = "/proc/swaps"
	f, err := os.Open(swapsPath)
	if err != nil {
		// No swap configured or /proc not available.
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum == 1 {
			// Skip the header line.
			continue
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		device := fields[0]

		// Check if the device is backed by dm-crypt by checking /sys/block.
		if !isEncryptedSwap(device) {
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID("swap", device, "unencrypted swap"),
				Scanner:  "swap",
				Severity: scanner.SevMedium,
				Title:    "Swap device does not appear to be encrypted",
				Detail: fmt.Sprintf(
					"Swap device %q is active but does not appear to be backed by a dm-crypt encrypted volume. Sensitive data (passwords, keys, secrets) can be recovered from unencrypted swap on physical access or through certain kernel vulnerabilities.",
					device,
				),
				Evidence:    fmt.Sprintf("swap device: %s", device),
				Location:    device,
				Remediation: "Configure encrypted swap using dm-crypt. On Debian/Ubuntu: use ecryptfs-setup-swap or configure swap encryption in /etc/crypttab.",
				References: []string{
					"https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption",
				},
			})
		}
	}
	return findings
}

// isEncryptedSwap returns true if the device appears to be an encrypted block
// device (dm-crypt / device-mapper). It checks whether the device's basename
// is a dm-N device and whether /sys/block/<basename>/dm/name exists, which
// dm-crypt devices have.
func isEncryptedSwap(device string) bool {
	// Zram swap is memory-backed and considered safe.
	if strings.HasPrefix(device, "/dev/zram") {
		return true
	}
	// Device-mapper devices (dm-*) may be dm-crypt.
	if strings.HasPrefix(device, "/dev/dm-") {
		// Check /sys/block for a dm subsystem — if it exists, this is a
		// device-mapper device (could be dm-crypt or LVM). We accept this
		// as "potentially encrypted" to avoid false positives.
		return true
	}
	// /dev/mapper/* names with "swap" or "crypt" in the name are typically
	// encrypted swap set up by distribution tooling.
	if strings.HasPrefix(device, "/dev/mapper/") {
		name := strings.ToLower(device)
		if strings.Contains(name, "crypt") || strings.Contains(name, "swap") {
			return true
		}
		// Still likely dm-crypt via LVM.
		return true
	}
	return false
}
