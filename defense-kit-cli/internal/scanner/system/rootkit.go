package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
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
	sysModulePath   string
	devPath         string
	procPath        string
}

// NewRootkitScanner creates a new RootkitScanner with production defaults.
func NewRootkitScanner() *RootkitScanner {
	return &RootkitScanner{
		procModulesPath: "/proc/modules",
		sysModulePath:   "/sys/module",
		devPath:         "/dev",
		procPath:        "/proc",
	}
}

func (s *RootkitScanner) Name() string            { return "rootkit" }
func (s *RootkitScanner) Category() string        { return "system" }
func (s *RootkitScanner) RequiresRoot() bool      { return true }
func (s *RootkitScanner) RequiredTools() []string { return nil }
func (s *RootkitScanner) OptionalTools() []string { return []string{"rkhunter", "chkrootkit"} }
func (s *RootkitScanner) Available() bool         { return true }
func (s *RootkitScanner) Description() string {
	return "Checks for rootkit indicators: suspicious kernel module names in /proc/modules, non-standard device files in /dev, and processes whose /proc/*/status PID count differs from the number of /proc/[0-9]* entries."
}

// Scan runs all rootkit detection checks and returns the findings.
func (s *RootkitScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	// Track findings by ID for deduplication.
	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	addFindings := func(ff []scanner.Finding) {
		for _, f := range ff {
			if !seenIDs[f.ID] {
				seenIDs[f.ID] = true
				findings = append(findings, f)
			}
		}
	}

	// Try rkhunter if ToolRunner is available.
	if opts.ToolRunner != nil && opts.ToolRunner.Available("rkhunter") {
		out, err := opts.ToolRunner.Run(ctx, "rkhunter", []string{
			"--check", "--skip-keypress", "--report-warnings-only",
		})
		if err == nil || len(out) > 0 {
			rkhunterFindings, parseErr := tools.ParseRkhunterOutput(out)
			if parseErr == nil {
				addFindings(rkhunterFindings)
			}
		}
	}

	// Always run native checks too.
	moduleFindings, err := s.checkKernelModules()
	if err == nil {
		addFindings(moduleFindings)
	}

	hidingFindings, err := s.checkHidingModules()
	if err == nil {
		addFindings(hidingFindings)
	}

	recentModuleFindings, err := s.checkRecentlyLoadedModules()
	if err == nil {
		addFindings(recentModuleFindings)
	}

	devFindings, err := s.checkDevFiles()
	if err == nil {
		addFindings(devFindings)
	}

	hiddenFindings, err := s.checkHiddenProcesses()
	if err == nil {
		addFindings(hiddenFindings)
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

// checkHidingModules compares /proc/modules against /sys/module/ directory.
// Modules present in /sys/module but absent from /proc/modules are hiding
// themselves — a strong rootkit indicator.
func (s *RootkitScanner) checkHidingModules() ([]scanner.Finding, error) {
	// Read modules visible via /proc/modules.
	procMods, err := s.readProcModuleNames()
	if err != nil {
		return nil, fmt.Errorf("checkHidingModules: %w", err)
	}

	// Read modules present in /sys/module/.
	sysMods, err := os.ReadDir(s.sysModulePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.sysModulePath, err)
	}

	var findings []scanner.Finding
	for _, entry := range sysMods {
		if !entry.IsDir() {
			continue
		}
		// /sys/module uses underscores; /proc/modules may use hyphens or underscores.
		name := entry.Name()
		normalized := strings.ReplaceAll(name, "-", "_")
		if procMods[normalized] {
			continue
		}
		loc := filepath.Join(s.sysModulePath, name)
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID(s.Name(), loc, "module hiding from proc/modules"),
			Scanner:     s.Name(),
			Severity:    scanner.SevCritical,
			Title:       "Kernel module hiding from /proc/modules",
			Detail:      fmt.Sprintf("Module %q is present in %s but does not appear in /proc/modules. A rootkit may be intercepting the module list to hide this module.", name, s.sysModulePath),
			Evidence:    fmt.Sprintf("present in /sys/module/%s, absent from /proc/modules", name),
			Location:    loc,
			Remediation: fmt.Sprintf("Investigate module %q with 'modinfo %s'. This may indicate a kernel-level rootkit. Consider booting from trusted media for a clean audit.", name, name),
		})
	}
	return findings, nil
}

// readProcModuleNames returns a set of module names (normalized with underscores)
// currently listed in /proc/modules.
func (s *RootkitScanner) readProcModuleNames() (map[string]bool, error) {
	f, err := os.Open(s.procModulesPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", s.procModulesPath, err)
	}
	defer f.Close()

	mods := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		normalized := strings.ReplaceAll(parts[0], "-", "_")
		mods[normalized] = true
	}
	return mods, sc.Err()
}

// recentModuleThreshold is how recently a module must have been loaded (based
// on /sys/module/*/initstate mtime) to be flagged as potentially suspicious.
const recentModuleThreshold = 10 * time.Minute

// checkRecentlyLoadedModules flags modules whose /sys/module/*/initstate file
// was modified very recently, which may indicate a module was just loaded.
func (s *RootkitScanner) checkRecentlyLoadedModules() ([]scanner.Finding, error) {
	sysMods, err := os.ReadDir(s.sysModulePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.sysModulePath, err)
	}

	now := time.Now()
	var findings []scanner.Finding

	for _, entry := range sysMods {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		initstatePath := filepath.Join(s.sysModulePath, name, "initstate")
		info, err := os.Stat(initstatePath)
		if err != nil {
			continue
		}
		age := now.Sub(info.ModTime())
		if age > recentModuleThreshold {
			continue
		}

		// Also flag modules with no/suspicious modinfo description.
		description := getModinfoDescription(name)
		descNote := ""
		if description == "" {
			descNote = " Module has no modinfo description, which is unusual for legitimate modules."
		}

		loc := initstatePath
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID(s.Name(), loc, "recently loaded kernel module"),
			Scanner:     s.Name(),
			Severity:    scanner.SevMedium,
			Title:       "Recently loaded kernel module",
			Detail:      fmt.Sprintf("Module %q was loaded within the last %s (initstate mtime: %s).%s Verify this is an expected module load.", name, recentModuleThreshold, info.ModTime().Format(time.RFC3339), descNote),
			Evidence:    fmt.Sprintf("module=%s initstate_mtime=%s age=%s", name, info.ModTime().Format(time.RFC3339), age.Round(time.Second)),
			Location:    loc,
			Remediation: fmt.Sprintf("Run 'modinfo %s' and verify the module is expected. If not, unload with 'rmmod %s' and investigate.", name, name),
		})
	}
	return findings, nil
}

// getModinfoDescription runs 'modinfo -F description <name>' and returns the
// trimmed output, or empty string if the command fails or produces no output.
func getModinfoDescription(name string) string {
	cmd := exec.Command("modinfo", "-F", "description", name)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// checkModinfoDescriptions flags loaded modules that have empty modinfo
// descriptions. Legitimate kernel modules almost always have a description;
// absence is unusual and warrants investigation.
func (s *RootkitScanner) checkModinfoDescriptions() ([]scanner.Finding, error) {
	procMods, err := s.readProcModuleNames()
	if err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	for name := range procMods {
		desc := getModinfoDescription(name)
		if desc != "" {
			continue
		}
		loc := s.procModulesPath
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID(s.Name(), loc, "no modinfo description: "+name),
			Scanner:     s.Name(),
			Severity:    scanner.SevMedium,
			Title:       "Kernel module with no description",
			Detail:      fmt.Sprintf("Module %q has no modinfo description. Legitimate kernel modules almost always include a description; absence may indicate a hand-compiled or malicious module.", name),
			Evidence:    fmt.Sprintf("module=%s description=(empty)", name),
			Location:    loc,
			Remediation: fmt.Sprintf("Run 'modinfo %s' to inspect the module. Unload with 'rmmod %s' if it is not expected.", name, name),
		})
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
