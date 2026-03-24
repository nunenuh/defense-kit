package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// PAMScanner scans /etc/pam.d/ configuration files for suspicious PAM modules.
type PAMScanner struct {
	pamDir string
}

// NewPAMScanner creates a new PAMScanner with default path.
func NewPAMScanner() *PAMScanner {
	return &PAMScanner{pamDir: "/etc/pam.d"}
}

// NewPAMScannerWithPath creates a scanner with custom path (for testing).
func NewPAMScannerWithPath(pamDir string) *PAMScanner {
	return &PAMScanner{pamDir: pamDir}
}

func (s *PAMScanner) Name() string           { return "pam" }
func (s *PAMScanner) Category() string       { return "environment" }
func (s *PAMScanner) RequiresRoot() bool     { return true }
func (s *PAMScanner) RequiredTools() []string { return nil }
func (s *PAMScanner) OptionalTools() []string { return nil }
func (s *PAMScanner) Available() bool        { return os.Geteuid() == 0 }
func (s *PAMScanner) Description() string {
	return "Scans /etc/pam.d/ configuration files for dangerous PAM modules such as pam_exec.so, pam_script.so, and pam_permit.so in auth context."
}

// pamModuleRule defines how to flag a specific PAM module.
type pamModuleRule struct {
	module      string
	authContext bool // if true, apply CRITICAL only when context is "auth"
	severity    scanner.Severity
	title       string
	detail      string
	remediation string
}

var pamRules = []pamModuleRule{
	{
		module:   "pam_exec.so",
		severity: scanner.SevHigh,
		title:    "pam_exec.so module found",
		detail:   "pam_exec.so executes arbitrary commands during PAM events and is commonly used for backdoors.",
		remediation: "Remove pam_exec.so from PAM configuration unless it is explicitly required and audited.",
	},
	{
		module:   "pam_script.so",
		severity: scanner.SevHigh,
		title:    "pam_script.so module found",
		detail:   "pam_script.so runs scripts during PAM authentication events and can be abused for persistence.",
		remediation: "Remove pam_script.so from PAM configuration unless it is explicitly required and audited.",
	},
	{
		module:      "pam_permit.so",
		authContext: true,
		severity:    scanner.SevHigh, // elevated to CRITICAL when context == "auth"
		title:       "pam_permit.so module found",
		detail:      "pam_permit.so unconditionally permits access; in an auth context this bypasses authentication entirely.",
		remediation: "Remove pam_permit.so from auth stacks; it should never appear in authentication configuration.",
	},
	{
		module:   "pam_debug.so",
		severity: scanner.SevMedium,
		title:    "pam_debug.so module found",
		detail:   "pam_debug.so logs detailed authentication information including credentials to syslog, which may expose sensitive data.",
		remediation: "Remove pam_debug.so from PAM configuration; it should only be used temporarily during debugging.",
	},
	{
		module:   "pam_succeed_if.so",
		severity: scanner.SevMedium,
		title:    "pam_succeed_if.so module found",
		detail:   "pam_succeed_if.so with broad or permissive conditions can weaken authentication by allowing access based on simple attribute checks.",
		remediation: "Review the pam_succeed_if.so conditions and ensure they are not overly permissive.",
	},
}

// Scan inspects all files in /etc/pam.d/ for dangerous modules.
func (s *PAMScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	findings, err := scanPAMDir(s.pamDir)
	if err != nil {
		return findings, err
	}
	findings = append(findings, checkUnownedPAMModules(s.pamDir)...)
	findings = append(findings, checkCommonAuthModified(filepath.Join(s.pamDir, "common-auth"))...)
	return findings, nil
}

// scanPAMDir scans all files in the given PAM configuration directory.
func scanPAMDir(dir string) ([]scanner.Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pam: cannot read %s: %w", dir, err)
	}

	var findings []scanner.Finding
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		ff, err := scanPAMFile(path)
		if err != nil {
			// Unreadable file — skip.
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, nil
}

// scanPAMFile scans a single PAM configuration file for suspicious modules.
func scanPAMFile(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding
	lineNum := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// PAM line format: <type> <control> <module-path> [module-arguments]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pamType := strings.ToLower(fields[0])
		modulePath := fields[2]
		// Module names may include a path prefix; compare only the basename.
		moduleName := filepath.Base(modulePath)

		for _, rule := range pamRules {
			if !strings.EqualFold(moduleName, rule.module) {
				continue
			}

			sev := rule.severity
			if rule.authContext && pamType == "auth" {
				sev = scanner.SevCritical
			}

			location := fmt.Sprintf("%s:%d", path, lineNum)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("pam", location, rule.title),
				Scanner:     "pam",
				Severity:    sev,
				Title:       rule.title,
				Detail:      rule.detail,
				Evidence:    line,
				Location:    location,
				Remediation: rule.remediation,
			})
		}
	}
	return findings, sc.Err()
}

// checkUnownedPAMModules scans all PAM config files for .so modules that are
// not owned by an installed package (via dpkg -S). Files that dpkg cannot
// account for are flagged HIGH.
func checkUnownedPAMModules(dir string) []scanner.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	// Collect all unique .so paths referenced in PAM config files.
	soFiles := make(map[string]string) // soPath -> "configFile:lineNum" location
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		lineNum := 0
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lineNum++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			modulePath := fields[2]
			if !strings.HasSuffix(modulePath, ".so") && !strings.Contains(modulePath, ".so") {
				continue
			}
			// Resolve absolute path: PAM modules without a leading slash live in
			// /lib/security/ or /lib/x86_64-linux-gnu/security/ etc.
			absPath := modulePath
			if !filepath.IsAbs(absPath) {
				// Store just the basename for dpkg lookup.
				absPath = filepath.Base(modulePath)
			}
			location := fmt.Sprintf("%s:%d", path, lineNum)
			if _, seen := soFiles[absPath]; !seen {
				soFiles[absPath] = location
			}
		}
		f.Close()
	}

	// Check each module against dpkg. If dpkg is not available, skip.
	if _, err := exec.LookPath("dpkg"); err != nil {
		return nil
	}

	var findings []scanner.Finding
	for soPath, location := range soFiles {
		out, err := exec.Command("dpkg", "-S", soPath).CombinedOutput()
		if err != nil && len(out) == 0 {
			// dpkg cannot find the file — it is not from an installed package.
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("pam", location, "unowned PAM module "+soPath),
				Scanner:     "pam",
				Severity:    scanner.SevHigh,
				Title:       "PAM module not owned by any installed package",
				Detail:      fmt.Sprintf("The PAM module %q is not tracked by dpkg. This may indicate a manually installed or malicious module.", soPath),
				Evidence:    soPath,
				Location:    location,
				Remediation: "Verify the origin of the module. If it is not required, remove it and restore a known-good PAM configuration.",
			})
		}
	}
	return findings
}

// checkCommonAuthModified checks whether /etc/pam.d/common-auth has been
// modified more recently than the libpam-runtime package was installed.
// A newer mtime is reported as MEDIUM (informational).
func checkCommonAuthModified(commonAuthPath string) []scanner.Finding {
	info, err := os.Stat(commonAuthPath)
	if err != nil {
		// File doesn't exist or isn't readable — skip.
		return nil
	}
	fileMtime := info.ModTime()

	// Try to determine when libpam-runtime was installed via dpkg.
	if _, err := exec.LookPath("dpkg"); err != nil {
		return nil
	}
	out, err := exec.Command("dpkg", "-l", "libpam-runtime").Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	// dpkg -l output doesn't include install time directly; use the package
	// info file mtime as a proxy for install time.
	pkgInfoPath := "/var/lib/dpkg/info/libpam-runtime.list"
	pkgInfo, err := os.Stat(pkgInfoPath)
	if err != nil {
		return nil
	}
	pkgInstallTime := pkgInfo.ModTime()

	// If common-auth was modified after the package was installed, flag it.
	if fileMtime.After(pkgInstallTime.Add(time.Minute)) {
		return []scanner.Finding{
			{
				ID:          scanner.GenerateFindingID("pam", commonAuthPath, "common-auth modified after package install"),
				Scanner:     "pam",
				Severity:    scanner.SevMedium,
				Title:       "common-auth modified after libpam-runtime install",
				Detail:      fmt.Sprintf("%s was last modified at %s, which is after the libpam-runtime package install time (%s). The file may have been tampered with.", commonAuthPath, fileMtime.Format(time.RFC3339), pkgInstallTime.Format(time.RFC3339)),
				Evidence:    fmt.Sprintf("file mtime: %s, package install time: %s", fileMtime.Format(time.RFC3339), pkgInstallTime.Format(time.RFC3339)),
				Location:    commonAuthPath,
				Remediation: "Review changes to /etc/pam.d/common-auth. If unexpected, restore from a known-good backup or reinstall libpam-runtime.",
			},
		}
	}
	return nil
}
