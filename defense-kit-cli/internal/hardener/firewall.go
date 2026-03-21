package hardener

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// FirewallHardener is a stub that will eventually remediate firewall findings.
type FirewallHardener struct{}

// NewFirewallHardener returns a new FirewallHardener.
func NewFirewallHardener() *FirewallHardener { return &FirewallHardener{} }

// Name returns "firewall".
func (fw *FirewallHardener) Name() string { return "firewall" }

// CanFix always returns false — implementation pending.
func (fw *FirewallHardener) CanFix(_ scanner.Finding) bool { return false }

// Preview returns an empty FixPlan.
func (fw *FirewallHardener) Preview(f scanner.Finding) FixPlan { return FixPlan{Finding: f} }

// Apply is a no-op stub.
func (fw *FirewallHardener) Apply(_ context.Context, _ FixPlan) error { return nil }

// Verify is a no-op stub.
func (fw *FirewallHardener) Verify(_ context.Context, _ FixPlan) error { return nil }

// Rollback is a no-op stub.
func (fw *FirewallHardener) Rollback(_ context.Context, _ FixPlan) error { return nil }
