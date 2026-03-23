package hardener

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const sysctlConfFilename = "99-defense-kit.conf"

// sysctlParam maps a sysctl parameter name to its secure value and a brief
// rationale comment.
type sysctlParam struct {
	param   string
	value   string
	comment string
}

// secureSysctlParams lists the kernel parameters the OS hardener enforces.
var secureSysctlParams = []sysctlParam{
	{"net.ipv4.ip_forward", "0", "Disable packet forwarding"},
	{"net.ipv4.conf.all.accept_redirects", "0", "Reject ICMP redirects"},
	{"net.ipv4.conf.all.send_redirects", "0", "Don't send ICMP redirects"},
	{"net.ipv4.conf.all.accept_source_route", "0", "Reject source routing"},
	{"net.ipv4.tcp_syncookies", "1", "SYN flood protection"},
	{"kernel.randomize_va_space", "2", "Enable ASLR"},
	{"kernel.sysrq", "0", "Disable magic SysRq"},
	{"kernel.dmesg_restrict", "1", "Restrict kernel messages"},
	{"fs.suid_dumpable", "0", "No core dumps for SUID"},
}

// osCanFixKeywords are lower-case title substrings the OS hardener handles.
var osCanFixKeywords = []string{
	"ip_forward",
	"forwarding",
	"accept_redirect",
	"send_redirect",
	"source_route",
	"syncookie",
	"randomize_va_space",
	"aslr",
	"sysrq",
	"dmesg_restrict",
	"suid_dumpable",
	"kernel parameter",
	"sysctl",
}

// osScannerSources are scanner names whose findings the OS hardener may fix.
var osScannerSources = map[string]bool{
	"firewall": true,
	"rootkit":  true,
}

// OSHardener remediates OS-level findings by enforcing sysctl parameters.
type OSHardener struct {
	sysctlDir string // directory that contains 99-defense-kit.conf
}

// NewOSHardener returns an OSHardener that writes to /etc/sysctl.d/.
func NewOSHardener() *OSHardener {
	return &OSHardener{sysctlDir: "/etc/sysctl.d"}
}

// NewOSHardenerWithPath returns an OSHardener that writes to the given
// directory. Intended for testing without touching real /etc/sysctl.d/.
func NewOSHardenerWithPath(sysctlDir string) *OSHardener {
	return &OSHardener{sysctlDir: sysctlDir}
}

// Name returns "os".
func (o *OSHardener) Name() string { return "os" }

// CanFix returns true when the finding can be addressed by applying sysctl
// parameters. It matches findings from "firewall" or "rootkit" scanners whose
// title contains known sysctl-related keywords, and any finding whose Metadata
// contains a "sysctl_param" key.
func (o *OSHardener) CanFix(f scanner.Finding) bool {
	// Special metadata key always accepted.
	if _, ok := f.Metadata["sysctl_param"]; ok {
		return true
	}

	if !osScannerSources[f.Scanner] {
		return false
	}

	lower := strings.ToLower(f.Title)
	for _, kw := range osCanFixKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// confPath returns the full path to the sysctl drop-in file.
func (o *OSHardener) confPath() string {
	return filepath.Join(o.sysctlDir, sysctlConfFilename)
}

// Preview builds a FixPlan describing the sysctl changes without applying them.
func (o *OSHardener) Preview(f scanner.Finding) FixPlan {
	confFile := o.confPath()

	createAction := FixAction{
		Type:   FileCreate,
		Target: confFile,
		Args:   nil,
	}

	applyAction := FixAction{
		Type:   CommandExec,
		Target: "sysctl",
		Args:   []string{"sysctl", "--system"},
	}

	rollbackStep := RollbackStep{
		Description: fmt.Sprintf("Remove %s and revert sysctl settings", confFile),
		Action: FixAction{
			Type:   FileDelete,
			Target: confFile,
		},
		BackupPath: "",
	}

	return FixPlan{
		Finding:     f,
		Description: fmt.Sprintf("Write secure sysctl parameters to %s and apply via sysctl --system", confFile),
		Actions:     []FixAction{createAction, applyAction},
		BackupPaths: map[string]string{},
		Rollback: RollbackPlan{
			Steps: []RollbackStep{rollbackStep},
		},
	}
}

// Apply writes the sysctl configuration file and then runs `sysctl --system`
// to activate all drop-in files. It uses exec.CommandContext — no shell.
func (o *OSHardener) Apply(ctx context.Context, _ FixPlan) error {
	if err := o.writeConf(); err != nil {
		return fmt.Errorf("os hardener: write conf: %w", err)
	}

	cmd := exec.CommandContext(ctx, "sysctl", "--system")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("os hardener: sysctl --system: %w\noutput: %s", err, out)
	}

	return nil
}

// Verify checks that every managed sysctl parameter reports the expected value.
func (o *OSHardener) Verify(ctx context.Context, _ FixPlan) error {
	for _, p := range secureSysctlParams {
		got, err := readSysctl(ctx, p.param)
		if err != nil {
			return fmt.Errorf("os hardener verify: read %q: %w", p.param, err)
		}
		if strings.TrimSpace(got) != p.value {
			return fmt.Errorf("os hardener verify: %s = %q, want %q", p.param, strings.TrimSpace(got), p.value)
		}
	}
	return nil
}

// Rollback removes the defense-kit sysctl drop-in and re-applies the remaining
// sysctl configuration to restore previous values.
func (o *OSHardener) Rollback(ctx context.Context, _ FixPlan) error {
	confFile := o.confPath()

	if err := os.Remove(confFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os hardener rollback: remove %q: %w", confFile, err)
	}

	cmd := exec.CommandContext(ctx, "sysctl", "--system")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("os hardener rollback: sysctl --system: %w\noutput: %s", err, out)
	}

	return nil
}

// writeConf creates or overwrites the defense-kit sysctl drop-in file with
// all managed parameters.
func (o *OSHardener) writeConf() error {
	confFile := o.confPath()

	var sb strings.Builder
	sb.WriteString("# Managed by defense-kit — do not edit manually\n")
	for _, p := range secureSysctlParams {
		sb.WriteString(fmt.Sprintf("# %s\n", p.comment))
		sb.WriteString(fmt.Sprintf("%s = %s\n", p.param, p.value))
	}

	if err := os.WriteFile(confFile, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("write %q: %w", confFile, err)
	}
	return nil
}

// readSysctl runs `sysctl -n {param}` and returns its trimmed output.
func readSysctl(ctx context.Context, param string) (string, error) {
	cmd := exec.CommandContext(ctx, "sysctl", "-n", param)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
