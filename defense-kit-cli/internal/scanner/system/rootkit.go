package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// standardDevices is the set of device node names that are expected in /dev/.
// Devices outside this set are considered suspicious.
var standardDevices = map[string]bool{
	"null":      true,
	"zero":      true,
	"random":    true,
	"urandom":   true,
	"full":      true,
	"tty":       true,
	"console":   true,
	"stdin":     true,
	"stdout":    true,
	"stderr":    true,
	"ptmx":      true,
	"kmsg":      true,
	"mem":       true,
	"port":      true,
	"core":      true,
	"fd":        true,
	"loop-control": true,
	"shm":       true,
	"mqueue":    true,
	"hugepages": true,
}

// suspiciousModulePatterns are substrings that indicate potentially malicious
// kernel module names.
var suspiciousModulePatterns = []string{
	"hide",
	"rootkit",
	"backdoor",
	"stealth",
	"ghost",
	"keylog",
	"hook",
	"intercept",
	"sniff",
	"inject",
}

// RootkitScanner checks for signs of rootkit activity: hidden kernel modules,
// suspicious device files in /dev, and processes hidden from /proc.
type RootkitScanner struct {
	procModulesPath string
	devPath         string
	procPath        string
}

// NewRootkitScanner creates a new RootkitScanner with production defaults.
func NewRootkitScanner() *RootkitScanner {
	return &RootkitScanner{
		procModulesPath: "/proc/modules",
		devPath:         "/dev",
		procPath:        "/proc",
	}
}

func (s *RootkitScanner) Name() string            { return "rootkit" }
func (s *RootkitScanner) Category() string        { return "system" }
func (s *RootkitScanner) RequiresRoot() bool      { return true }
func (s *RootkitScanner) RequiredTools() []string { return nil }
func (s *RootkitScanner) OptionalTools() []string { return nil }
func (s *RootkitScanner) Available() bool         { return true }
func (s *RootkitScanner) Description() string {
	return "Checks for rootkit indicators: suspicious kernel module names in /proc/modules, non-standard device files in /dev, and processes whose /proc/*/status PID count differs from the number of /proc/[0-9]* entries."
}

// Scan runs all rootkit detection checks and returns the findings.
func (s *RootkitScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	moduleFindings, err := s.checkKernelModules()
	if err == nil {
		findings = append(findings, moduleFindings...)
	}

	devFindings, err := s.checkDevFiles()
	if err == nil {
		findings = append(findings, devFindings...)
	}

	hiddenFindings, err := s.checkHiddenProcesses()
	if err == nil {
		findings = append(findings, hiddenFindings...)
	}

	return findings, nil
}

// checkKernelModules reads /proc/modules and flags entries whose names match
// known suspicious patterns.
func (s *RootkitScanner) checkKernelModules() ([]scanner.Finding, error) {
	f, err := os.Open(s.procModulesPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", s.procModulesPath, err)
	}
	defer f.Close()

	var findings []scanner.Finding

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// /proc/modules format: <name> <size> <refcount> <deps> <state> <addr>
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		modName := strings.ToLower(parts[0])

		for _, pattern := range suspiciousModulePatterns {
			if strings.Contains(modName, pattern) {
				loc := s.procModulesPath
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID(s.Name(), loc, "suspicious kernel module: "+parts[0]),
					Scanner:     s.Name(),
					Severity:    scanner.SevCritical,
					Title:       "Suspicious kernel module detected",
					Detail:      fmt.Sprintf("Kernel module %q matches pattern %q, which is associated with rootkit activity.", parts[0], pattern),
					Evidence:    line,
					Location:    loc,
					Remediation: fmt.Sprintf("Investigate module %q with 'modinfo %s' and remove if not legitimate.", parts[0], parts[0]),
				})
				break // one finding per module
			}
		}
	}

	if err := sc.Err(); err != nil {
		return findings, fmt.Errorf("reading %s: %w", s.procModulesPath, err)
	}

	return findings, nil
}

// checkDevFiles scans /dev for device files whose names are not in the
// standard allow-list. Non-standard character/block devices are flagged.
func (s *RootkitScanner) checkDevFiles() ([]scanner.Finding, error) {
	entries, err := os.ReadDir(s.devPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.devPath, err)
	}

	var findings []scanner.Finding

	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)

		// Skip directories and known standard devices.
		if entry.IsDir() {
			continue
		}
		if standardDevices[lower] {
			continue
		}

		// Allow common device families by prefix.
		if isStandardDeviceFamily(lower) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Only flag character and block devices (not sockets, pipes, etc.).
		mode := info.Mode()
		if mode&os.ModeDevice == 0 && mode&os.ModeCharDevice == 0 {
			continue
		}

		loc := filepath.Join(s.devPath, name)
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID(s.Name(), loc, "suspicious device file"),
			Scanner:     s.Name(),
			Severity:    scanner.SevCritical,
			Title:       "Suspicious device file in /dev",
			Detail:      fmt.Sprintf("Non-standard device file %q found in /dev. Rootkits often create device files for covert communication channels.", name),
			Evidence:    fmt.Sprintf("path: %s, mode: %s", loc, mode.String()),
			Location:    loc,
			Remediation: fmt.Sprintf("Investigate %s and remove if not associated with a legitimate driver.", loc),
		})
	}

	return findings, nil
}

// isStandardDeviceFamily returns true for device names that belong to common
// Linux device families (e.g., sda, tty0, loop0, nvme0n1, ...).
func isStandardDeviceFamily(name string) bool {
	prefixes := []string{
		"sd", "hd", "vd", "xvd", "nvme", "mmcblk", // block devices
		"tty", "pts", "pty",                          // terminals
		"loop",                                        // loop devices
		"dm-",                                         // device-mapper
		"md",                                          // software RAID
		"sg",                                          // SCSI generic
		"sr",                                          // optical
		"net/",                                        // network
		"usb",                                         // USB
		"input/",                                      // input devices
		"snd/",                                        // sound
		"dri/",                                        // DRM
		"bus/",                                        // bus devices
		"cpu/",                                        // CPU devices
		"mapper/",                                     // device-mapper
		"disk/",                                       // disk by-id/by-path
		"char/",                                       // character device classes
		"block/",                                      // block device classes
		"bsg/",                                        // block SCSI generic
		"rfkill",                                      // rfkill
		"watchdog",                                    // watchdog
		"video",                                       // video devices
		"fb",                                          // framebuffer
		"hidraw",                                      // HID raw
		"i2c",                                         // I2C
		"spi",                                         // SPI
		"rtc",                                         // real-time clock
		"autofs",                                      // autofs
		"fuse",                                        // FUSE
		"kvm",                                         // KVM virtualization
		"vhost",                                       // vhost
		"vfio",                                        // VFIO
		"vsock",                                       // vsock
		"zram",                                        // zram
		"pmem",                                        // persistent memory
		"dax",                                         // direct access
	}

	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// checkHiddenProcesses compares the count of numeric /proc entries (visible
// PIDs) against the count of unique PIDs reported in /proc/*/status files.
// A discrepancy suggests a rootkit is hiding processes.
func (s *RootkitScanner) checkHiddenProcesses() ([]scanner.Finding, error) {
	// Count /proc/[0-9]* directories — these are the PIDs the kernel exposes.
	entries, err := os.ReadDir(s.procPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.procPath, err)
	}

	visiblePIDs := map[int]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		visiblePIDs[pid] = true
	}

	// Read PIDs from /proc/*/status — the kernel writes these, so a rootkit
	// that intercepts getdents() will hide entries from the directory listing
	// but may leave status files readable via direct path.
	statusPIDs := map[int]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		statusPath := filepath.Join(s.procPath, e.Name(), "status")
		pid := parsePIDFromStatus(statusPath)
		if pid > 0 {
			statusPIDs[pid] = true
		}
	}

	var findings []scanner.Finding

	// Look for PIDs in status files that are not in the directory listing.
	for pid := range statusPIDs {
		if !visiblePIDs[pid] {
			loc := s.procPath
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID(s.Name(), loc, fmt.Sprintf("hidden process PID %d", pid)),
				Scanner:     s.Name(),
				Severity:    scanner.SevCritical,
				Title:       "Hidden process detected",
				Detail:      fmt.Sprintf("Process with PID %d is present in /proc/*/status but not in the /proc directory listing, indicating a rootkit may be hiding it.", pid),
				Evidence:    fmt.Sprintf("PID %d visible in status files but missing from /proc directory listing", pid),
				Location:    loc,
				Remediation: "Investigate PID " + strconv.Itoa(pid) + " with a trusted live-boot environment. Consider a full system audit.",
			})
		}
	}

	return findings, nil
}

// parsePIDFromStatus reads the Pid: field from a /proc/<pid>/status file.
func parsePIDFromStatus(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Pid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, err := strconv.Atoi(parts[1])
				if err == nil {
					return pid
				}
			}
		}
	}
	return 0
}
