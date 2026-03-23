package hardener

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// firewallCanFixKeywords are lower-case title substrings the firewall hardener handles.
var firewallCanFixKeywords = []string{
	"missing firewall",
	"no firewall",
	"firewall disabled",
	"firewall not enabled",
	"firewall not active",
	"firewall inactive",
	"ip_forward enabled",
	"ip forward enabled",
	"ip forwarding enabled",
}

// FirewallHardener remediates firewall-related findings using ufw.
type FirewallHardener struct {
	// dryRun skips actual ufw commands; used in unit tests.
	dryRun bool
}

// NewFirewallHardener returns a production FirewallHardener.
func NewFirewallHardener() *FirewallHardener {
	return &FirewallHardener{}
}

// NewFirewallHardenerForTest returns a FirewallHardener that skips actual ufw
// commands. Use this in unit tests where ufw is unavailable.
func NewFirewallHardenerForTest() *FirewallHardener {
	return &FirewallHardener{dryRun: true}
}

// Name returns "firewall".
func (fw *FirewallHardener) Name() string { return "firewall" }

// CanFix returns true when the finding comes from the "firewall" scanner and
// its title matches a known fixable keyword.
func (fw *FirewallHardener) CanFix(f scanner.Finding) bool {
	if f.Scanner != "firewall" {
		return false
	}
	lower := strings.ToLower(f.Title)
	for _, kw := range firewallCanFixKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// Preview returns a FixPlan describing the ufw commands that will run.
func (fw *FirewallHardener) Preview(f scanner.Finding) FixPlan {
	actions := []FixAction{
		{Type: CommandExec, Target: "ufw", Args: []string{"ufw", "default", "deny", "incoming"}},
		{Type: CommandExec, Target: "ufw", Args: []string{"ufw", "default", "allow", "outgoing"}},
		{Type: CommandExec, Target: "ufw", Args: []string{"ufw", "allow", "22/tcp", "comment", "SSH"}},
		{Type: CommandExec, Target: "ufw", Args: []string{"ufw", "--force", "enable"}},
	}

	rollbackStep := RollbackStep{
		Description: "Disable ufw to restore pre-hardening firewall state",
		Action: FixAction{
			Type:   CommandExec,
			Target: "ufw",
			Args:   []string{"ufw", "disable"},
		},
	}

	return FixPlan{
		Finding: f,
		Description: "Configure ufw: deny incoming, allow outgoing, always allow SSH (22/tcp), then enable firewall. " +
			"SSH is allowed FIRST to prevent lockout.",
		Actions:     actions,
		BackupPaths: map[string]string{},
		Rollback: RollbackPlan{
			Steps: []RollbackStep{rollbackStep},
		},
	}
}

// Apply runs the ufw commands to configure and enable the firewall.
// SSH (port 22) is always allowed before enabling to prevent lockout.
func (fw *FirewallHardener) Apply(ctx context.Context, _ FixPlan) error {
	if fw.dryRun {
		return nil
	}

	commands := [][]string{
		{"ufw", "default", "deny", "incoming"},
		{"ufw", "default", "allow", "outgoing"},
		// CRITICAL: Allow SSH before enabling to prevent lockout.
		{"ufw", "allow", "22/tcp", "comment", "SSH"},
		{"ufw", "--force", "enable"},
	}

	for _, argv := range commands {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("firewall hardener: %v: %w\noutput: %s", argv, err, out)
		}
	}

	return nil
}

// Verify runs `ufw status` and checks that the firewall is active.
func (fw *FirewallHardener) Verify(ctx context.Context, _ FixPlan) error {
	if fw.dryRun {
		return nil
	}

	cmd := exec.CommandContext(ctx, "ufw", "status")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("firewall hardener verify: ufw status: %w", err)
	}

	if !strings.Contains(string(out), "Status: active") {
		return fmt.Errorf("firewall hardener verify: ufw is not active; output: %s", string(out))
	}

	return nil
}

// Rollback disables ufw to restore the pre-hardening firewall state.
func (fw *FirewallHardener) Rollback(ctx context.Context, _ FixPlan) error {
	if fw.dryRun {
		return nil
	}

	cmd := exec.CommandContext(ctx, "ufw", "disable")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("firewall hardener rollback: ufw disable: %w\noutput: %s", err, out)
	}

	return nil
}
