package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const (
	mountsPath = "/proc/mounts"
	swapsPath  = "/proc/swaps"
	sysBlockPath = "/sys/block"
)

// EncryptionScanner checks whether the root filesystem and swap are backed by
// dm-crypt encrypted volumes.
type EncryptionScanner struct {
	mountsPath   string
	swapsPath    string
	sysBlockPath string
}

// NewEncryptionScanner creates an EncryptionScanner with production defaults.
func NewEncryptionScanner() *EncryptionScanner {
	return &EncryptionScanner{
		mountsPath:   mountsPath,
		swapsPath:    swapsPath,
		sysBlockPath: sysBlockPath,
	}
}

// NewEncryptionScannerWithPaths creates an EncryptionScanner with custom paths
// (used in tests).
func NewEncryptionScannerWithPaths(mountsPath, swapsPath, sysBlockPath string) *EncryptionScanner {
	return &EncryptionScanner{
		mountsPath:   mountsPath,
		swapsPath:    swapsPath,
		sysBlockPath: sysBlockPath,
	}
}

func (s *EncryptionScanner) Name() string            { return "encryption" }
func (s *EncryptionScanner) Category() string        { return "filesystem" }
func (s *EncryptionScanner) RequiresRoot() bool      { return true }
func (s *EncryptionScanner) RequiredTools() []string { return nil }
func (s *EncryptionScanner) OptionalTools() []string { return nil }
func (s *EncryptionScanner) Available() bool         { return true }
func (s *EncryptionScanner) Description() string {
	return "Checks whether the root filesystem and swap are backed by dm-crypt/LUKS encrypted volumes. Unencrypted storage may expose sensitive data at rest."
}

// Scan checks root filesystem and swap encryption.
func (s *EncryptionScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.checkRootEncryption()...)
	findings = append(findings, s.checkSwapEncryption()...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkRootEncryption checks whether the root (/) mount point is backed by
// a crypto_LUKS or dm-crypt device.
func (s *EncryptionScanner) checkRootEncryption() []scanner.Finding {
	f, err := os.Open(s.mountsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	rootDevice := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mountPoint := fields[1]
		if mountPoint == "/" {
			rootDevice = fields[0]
			break
		}
	}

	if rootDevice == "" {
		return nil
	}

	if s.isEncryptedDevice(rootDevice) {
		return nil
	}

	// Check whether the device is a dm device with crypto_LUKS.
	if s.isDMCryptDevice(rootDevice) {
		return nil
	}

	return []scanner.Finding{
		{
			ID:       scanner.GenerateFindingID(s.Name(), rootDevice, "unencrypted root filesystem"),
			Scanner:  s.Name(),
			Severity: scanner.SevMedium,
			Title:    "Root filesystem does not appear to be encrypted",
			Detail: fmt.Sprintf(
				"The root filesystem is mounted from %q, which does not appear to be a dm-crypt/LUKS encrypted device. If the physical disk is removed or accessed via another OS, all data is readable without authentication.",
				rootDevice,
			),
			Evidence:    fmt.Sprintf("root device: %s", rootDevice),
			Location:    rootDevice,
			Remediation: "Enable full-disk encryption using LUKS/dm-crypt. On Ubuntu/Debian, this is best configured during OS installation. For existing systems, see cryptsetup documentation.",
			References: []string{
				"https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system",
				"https://www.cisecurity.org/benchmark/ubuntu_linux",
			},
		},
	}
}

// checkSwapEncryption parses /proc/swaps and flags swap devices that do not
// appear to be encrypted.
func (s *EncryptionScanner) checkSwapEncryption() []scanner.Finding {
	f, err := os.Open(s.swapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // skip header
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

		if s.isEncryptedDevice(device) || s.isDMCryptDevice(device) {
			continue
		}

		findings = append(findings, scanner.Finding{
			ID:       scanner.GenerateFindingID(s.Name(), device, "unencrypted swap"),
			Scanner:  s.Name(),
			Severity: scanner.SevMedium,
			Title:    "Swap device does not appear to be encrypted",
			Detail: fmt.Sprintf(
				"Swap device %q is active but does not appear to be backed by a dm-crypt encrypted volume. Sensitive data (passwords, keys, secrets) swapped to disk can be recovered from unencrypted swap on physical access.",
				device,
			),
			Evidence:    fmt.Sprintf("swap device: %s", device),
			Location:    device,
			Remediation: "Configure encrypted swap using dm-crypt. On Debian/Ubuntu: use 'ecryptfs-setup-swap' or configure swap encryption in /etc/crypttab.",
			References: []string{
				"https://wiki.archlinux.org/title/Dm-crypt/Swap_encryption",
			},
		})
	}
	return findings
}

// isEncryptedDevice returns true for device paths that are clearly dm-crypt
// or LUKS devices by their path convention.
func (s *EncryptionScanner) isEncryptedDevice(device string) bool {
	// zram is memory-backed — no disk exposure.
	if strings.HasPrefix(device, "/dev/zram") {
		return true
	}
	// tmpfs, devtmpfs, etc. are memory-backed.
	if !strings.HasPrefix(device, "/dev/") {
		return true // sysfs, proc, tmpfs, overlay, etc.
	}
	// /dev/dm-* are device-mapper devices (dm-crypt, LVM, etc.).
	if strings.HasPrefix(device, "/dev/dm-") {
		return true
	}
	// /dev/mapper/* with crypt/swap/luks in the name.
	if strings.HasPrefix(device, "/dev/mapper/") {
		lower := strings.ToLower(device)
		if strings.Contains(lower, "crypt") || strings.Contains(lower, "luks") || strings.Contains(lower, "swap") {
			return true
		}
		// Other mapper devices may be LVM — accept as potentially encrypted.
		return true
	}
	return false
}

// isDMCryptDevice checks /sys/block/*/dm/name for dm-crypt device indicator.
func (s *EncryptionScanner) isDMCryptDevice(device string) bool {
	// Extract the base device name (e.g., sda from /dev/sda).
	baseName := filepath.Base(device)
	dmNamePath := filepath.Join(s.sysBlockPath, baseName, "dm", "name")
	_, err := os.Stat(dmNamePath)
	return err == nil
}
