package system_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/system"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultOpts() scanner.ScanOptions {
	return scanner.ScanOptions{}
}

// verifyInterfaceCompliance is a compile-time check that all system scanners
// satisfy the scanner.Scanner interface.
func verifyInterfaceCompliance() {
	var _ scanner.Scanner = (*system.RootkitScanner)(nil)
	var _ scanner.Scanner = (*system.BootScanner)(nil)
	var _ scanner.Scanner = (*system.LogsScanner)(nil)
	var _ scanner.Scanner = (*system.PackageMgrScanner)(nil)
	var _ scanner.Scanner = (*system.SysctlScanner)(nil)
	var _ scanner.Scanner = (*system.ServicesScanner)(nil)
	var _ scanner.Scanner = (*system.MACScanner)(nil)
	var _ scanner.Scanner = (*system.UpdatesScanner)(nil)
	var _ scanner.Scanner = (*system.AuditdScanner)(nil)
}

// ---------------------------------------------------------------------------
// RootkitScanner — interface tests
// ---------------------------------------------------------------------------

func TestRootkitScanner_Interface(t *testing.T) {
	s := system.NewRootkitScanner()

	if got := s.Name(); got != "rootkit" {
		t.Errorf("Name() = %q, want %q", got, "rootkit")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Errorf("RequiredTools() = %v, want nil", s.RequiredTools())
	}
}

// TestRootkitScanner_Scan_DoesNotPanic verifies that Scan completes without
// panicking on a real host. We cannot reliably mock /proc/modules, so we only
// assert that the call returns without error or panic. Findings may or may not
// be present depending on the host environment.
func TestRootkitScanner_Scan_DoesNotPanic(t *testing.T) {
	s := system.NewRootkitScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	// err may be non-nil when running without root; that is acceptable.
	// We only care that nothing panicked and that any returned findings have
	// the required fields populated.
	if err != nil {
		t.Logf("Scan returned error (may be expected without root): %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding has empty ID: %+v", f)
		}
		if f.Scanner == "" {
			t.Errorf("finding has empty Scanner: %+v", f)
		}
		if f.Title == "" {
			t.Errorf("finding has empty Title: %+v", f)
		}
		if f.Severity < scanner.SevLow || f.Severity > scanner.SevCritical {
			t.Errorf("finding has invalid Severity %d: %+v", f.Severity, f)
		}
	}
}

// ---------------------------------------------------------------------------
// BootScanner — interface tests
// ---------------------------------------------------------------------------

func TestBootScanner_Interface(t *testing.T) {
	s := system.NewBootScanner()

	if got := s.Name(); got != "boot" {
		t.Errorf("Name() = %q, want %q", got, "boot")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestBootScanner_ScanDoesNotPanic(t *testing.T) {
	s := system.NewBootScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	_ = findings // real scanner may find issues, that's fine
}

// ---------------------------------------------------------------------------
// LogsScanner — interface tests
// ---------------------------------------------------------------------------

func TestLogsScanner_Interface(t *testing.T) {
	s := system.NewLogsScanner()

	if got := s.Name(); got != "logs" {
		t.Errorf("Name() = %q, want %q", got, "logs")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestLogsScanner_Scan_DoesNotPanic(t *testing.T) {
	s := system.NewLogsScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	// err is acceptable (e.g., no /var/log/auth.log on this host).
	if err != nil {
		t.Logf("Scan returned error (may be expected in test environment): %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding has empty ID: %+v", f)
		}
		if f.Scanner == "" {
			t.Errorf("finding has empty Scanner: %+v", f)
		}
		if f.Title == "" {
			t.Errorf("finding has empty Title: %+v", f)
		}
		if f.Severity < scanner.SevLow || f.Severity > scanner.SevCritical {
			t.Errorf("finding has invalid Severity %d: %+v", f.Severity, f)
		}
	}
}

// ---------------------------------------------------------------------------
// PackageMgrScanner — interface tests
// ---------------------------------------------------------------------------

func TestPackageMgrScanner_Interface(t *testing.T) {
	s := system.NewPackageMgrScanner()

	if got := s.Name(); got != "package_manager" {
		t.Errorf("Name() = %q, want %q", got, "package_manager")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPackageMgrScanner_StubReturnsNoFindings(t *testing.T) {
	s := system.NewPackageMgrScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("stub Scan should return 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// SysctlScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestSysctlScanner_Interface(t *testing.T) {
	s := system.NewSysctlScanner()

	if got := s.Name(); got != "sysctl" {
		t.Errorf("Name() = %q, want %q", got, "sysctl")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Errorf("RequiredTools() = %v, want nil", s.RequiredTools())
	}
}

func TestSysctlScanner_DoesNotPanic(t *testing.T) {
	s := system.NewSysctlScanner()
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Logf("Scan returned error (may be expected in test environment): %v", err)
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding has empty ID: %+v", f)
		}
		if f.Scanner != "sysctl" {
			t.Errorf("finding Scanner = %q, want sysctl", f.Scanner)
		}
		if f.Metadata["sysctl_param"] == "" {
			t.Errorf("finding missing sysctl_param metadata: %+v", f)
		}
	}
}

// TestSysctlScanner_DetectsInsecureIPForward creates a fake /proc/sys tree
// with ip_forward=1 and verifies that a HIGH finding is produced.
func TestSysctlScanner_DetectsInsecureIPForward(t *testing.T) {
	dir := t.TempDir()
	paramPath := filepath.Join(dir, "net", "ipv4", "ip_forward")
	if err := os.MkdirAll(filepath.Dir(paramPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(paramPath, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := system.NewSysctlScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Metadata["sysctl_param"] == "net.ipv4.ip_forward" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for ip_forward=1, got: %+v", findings)
	}
}

// TestSysctlScanner_NoFindingForSecureValues verifies that when all params are
// at their secure values no findings are produced.
func TestSysctlScanner_NoFindingForSecureValues(t *testing.T) {
	dir := t.TempDir()

	secure := map[string]string{
		"net/ipv4/ip_forward":                    "0",
		"kernel/randomize_va_space":               "2",
		"kernel/sysrq":                            "0",
		"kernel/dmesg_restrict":                   "1",
		"fs/suid_dumpable":                        "0",
		"net/ipv4/conf/all/accept_redirects":       "0",
		"net/ipv4/conf/all/send_redirects":         "0",
		"net/ipv4/tcp_syncookies":                  "1",
	}
	for rel, val := range secure {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	s := system.NewSysctlScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for all-secure sysctl values, got %d: %+v", len(findings), findings)
	}
}

// ---------------------------------------------------------------------------
// ServicesScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestServicesScanner_Interface(t *testing.T) {
	s := system.NewServicesScanner()

	if got := s.Name(); got != "services" {
		t.Errorf("Name() = %q, want %q", got, "services")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestServicesScanner_DoesNotPanic(t *testing.T) {
	s := system.NewServicesScanner()
	_, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Logf("Scan returned error (may be expected in test environment): %v", err)
	}
}

// TestServicesScanner_DetectsInsecureService creates a fake /proc tree
// containing a telnetd comm file and verifies a HIGH finding is produced.
func TestServicesScanner_DetectsInsecureService(t *testing.T) {
	dir := t.TempDir()
	pidDir := filepath.Join(dir, "1234")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("telnetd\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := system.NewServicesScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Metadata["service_name"] == "telnetd" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for telnetd, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// MACScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestMACScanner_Interface(t *testing.T) {
	s := system.NewMACScanner()

	if got := s.Name(); got != "mac" {
		t.Errorf("Name() = %q, want %q", got, "mac")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestMACScanner_DoesNotPanic(t *testing.T) {
	s := system.NewMACScanner()
	_, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
}

// TestMACScanner_DetectsNoMAC uses non-existent paths to simulate a system
// where neither AppArmor nor SELinux is installed, expecting a MEDIUM finding.
func TestMACScanner_DetectsNoMAC(t *testing.T) {
	dir := t.TempDir()
	s := system.NewMACScannerWithPaths(
		filepath.Join(dir, "nonexistent_apparmor"),
		filepath.Join(dir, "nonexistent_selinux"),
	)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "mac" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for no MAC, got: %+v", findings)
	}
}

// TestMACScanner_AppArmorEnabled creates a fake apparmor enabled file with
// "Y" and verifies no "no MAC" finding is produced.
func TestMACScanner_AppArmorEnabled(t *testing.T) {
	dir := t.TempDir()
	appArmorPath := filepath.Join(dir, "apparmor_enabled")
	if err := os.WriteFile(appArmorPath, []byte("Y\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := system.NewMACScannerWithPaths(
		appArmorPath,
		filepath.Join(dir, "nonexistent_selinux"),
	)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	// There should be no "no MAC" MEDIUM finding.
	for _, f := range findings {
		if f.Title == "No mandatory access control system is enabled" {
			t.Errorf("unexpected 'no MAC' finding when AppArmor is enabled: %+v", f)
		}
	}
}

// TestMACScanner_SELinuxEnforcing creates a fake selinux enforce file with "1"
// and verifies no "no MAC" finding is produced.
func TestMACScanner_SELinuxEnforcing(t *testing.T) {
	dir := t.TempDir()
	selinuxPath := filepath.Join(dir, "selinux_enforce")
	if err := os.WriteFile(selinuxPath, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := system.NewMACScannerWithPaths(
		filepath.Join(dir, "nonexistent_apparmor"),
		selinuxPath,
	)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "No mandatory access control system is enabled" {
			t.Errorf("unexpected 'no MAC' finding when SELinux is enforcing: %+v", f)
		}
	}
}

// TestMACScanner_SELinuxPermissive creates a fake selinux enforce file with "0"
// and verifies a LOW finding is produced.
func TestMACScanner_SELinuxPermissive(t *testing.T) {
	dir := t.TempDir()
	selinuxPath := filepath.Join(dir, "selinux_enforce")
	if err := os.WriteFile(selinuxPath, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s := system.NewMACScannerWithPaths(
		filepath.Join(dir, "nonexistent_apparmor"),
		selinuxPath,
	)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevLow && f.Scanner == "mac" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected LOW finding for SELinux permissive mode, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// UpdatesScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestUpdatesScanner_Interface(t *testing.T) {
	s := system.NewUpdatesScanner()

	if got := s.Name(); got != "updates" {
		t.Errorf("Name() = %q, want %q", got, "updates")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if s.RequiresRoot() {
		t.Error("RequiresRoot() should be false")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestUpdatesScanner_DoesNotPanic(t *testing.T) {
	s := system.NewUpdatesScanner()
	_, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
}

// TestUpdatesScanner_DetectsMissingAutoUpgrades uses a path that does not
// exist to simulate no unattended-upgrades config, expecting a MEDIUM finding.
func TestUpdatesScanner_DetectsMissingAutoUpgrades(t *testing.T) {
	dir := t.TempDir()
	s := system.NewUpdatesScannerWithPaths(
		filepath.Join(dir, "nonexistent"),
		filepath.Join(dir, "pkgcache.bin"),
	)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "updates" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for missing auto-upgrades, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// AuditdScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestAuditdScanner_Interface(t *testing.T) {
	s := system.NewAuditdScanner()

	if got := s.Name(); got != "auditd" {
		t.Errorf("Name() = %q, want %q", got, "auditd")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// TestAuditdScanner_DetectsNotRunning creates an empty fake /proc tree and
// verifies a HIGH finding is produced for auditd not running.
func TestAuditdScanner_DetectsNotRunning(t *testing.T) {
	dir := t.TempDir()
	s := system.NewAuditdScannerWithPath(dir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevHigh && f.Scanner == "auditd" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected HIGH finding for auditd not running, got: %+v", findings)
	}
}

// TestAuditdScanner_RunningAuditd creates a fake /proc tree with an auditd
// comm file and verifies no "not running" finding is produced.
func TestAuditdScanner_RunningAuditd(t *testing.T) {
	dir := t.TempDir()
	pidDir := filepath.Join(dir, "999")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("auditd\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := system.NewAuditdScannerWithPath(dir)
	// No ToolRunner — so rule checks are skipped. We only verify no
	// "auditd not running" finding appears.
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "auditd is not running" {
			t.Errorf("unexpected 'not running' finding when auditd is present: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// EBPFScanner — interface and detection tests
// ---------------------------------------------------------------------------

func TestEBPFScanner_Interface(t *testing.T) {
	s := system.NewEBPFScanner()

	if got := s.Name(); got != "ebpf" {
		t.Errorf("Name() = %q, want %q", got, "ebpf")
	}
	if got := s.Category(); got != "system" {
		t.Errorf("Category() = %q, want %q", got, "system")
	}
	if !s.RequiresRoot() {
		t.Error("RequiresRoot() should be true")
	}
	if !s.Available() {
		t.Error("Available() should be true")
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.RequiredTools() != nil {
		t.Errorf("RequiredTools() = %v, want nil", s.RequiredTools())
	}
	optTools := s.OptionalTools()
	if len(optTools) == 0 {
		t.Error("OptionalTools() should advertise bpftool")
	}

	var _ scanner.Scanner = s
}

func TestEBPFScanner_DoesNotPanic(t *testing.T) {
	s := system.NewEBPFScanner()
	// Scan may return no findings (bpftool absent) or findings — both are fine.
	_, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Logf("Scan returned error (may be expected without root): %v", err)
	}
}

// TestEBPFScanner_DetectsUnprivilegedBPF creates a fake /proc/sys tree with
// kernel.unprivileged_bpf_disabled=0 and verifies a MEDIUM finding is produced.
func TestEBPFScanner_DetectsUnprivilegedBPF(t *testing.T) {
	dir := t.TempDir()

	// Write the sysctl file that the scanner reads via procSysPath.
	sysctlDir := filepath.Join(dir, "kernel")
	if err := os.MkdirAll(sysctlDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sysctlDir, "unprivileged_bpf_disabled"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// dir acts as the /proc/sys base; nonexistent raw path → no raw socket finding.
	s := system.NewEBPFScannerWithPaths(filepath.Join(dir, "nonexistent-raw"), dir)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "ebpf" &&
			f.Title == "Unprivileged eBPF is enabled" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Evidence == "" {
				t.Error("finding has empty Evidence")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for unprivileged_bpf_disabled=0, got: %+v", findings)
	}
}

// TestEBPFScanner_DetectsRawSockets creates a fake /proc/net/raw file with
// one entry and verifies a MEDIUM finding is produced.
func TestEBPFScanner_DetectsRawSockets(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw")

	// Write a minimal /proc/net/raw with one socket entry.
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	content += "   0: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0\n"
	if err := os.WriteFile(rawPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := system.NewEBPFScannerWithProcNetRaw(rawPath)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.SevMedium && f.Scanner == "ebpf" &&
			f.Title == "Raw sockets detected" {
			found = true
			if f.ID == "" {
				t.Error("finding has empty ID")
			}
			if f.Location == "" {
				t.Error("finding has empty Location")
			}
		}
	}
	if !found {
		t.Errorf("expected MEDIUM finding for raw sockets, got: %+v", findings)
	}
}

// TestEBPFScanner_NoFindingsForEmptyRaw verifies that an empty /proc/net/raw
// (header only) produces no raw-socket finding.
func TestEBPFScanner_NoFindingsForEmptyRaw(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw")
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := os.WriteFile(rawPath, []byte(header), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := system.NewEBPFScannerWithProcNetRaw(rawPath)
	findings, err := s.Scan(context.Background(), defaultOpts())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	for _, f := range findings {
		if f.Title == "Raw sockets detected" {
			t.Errorf("unexpected raw-socket finding for empty /proc/net/raw: %+v", f)
		}
	}
}
