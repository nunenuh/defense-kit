package hardener

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// OSHardener is a stub that will eventually remediate OS-level findings.
type OSHardener struct{}

// NewOSHardener returns a new OSHardener.
func NewOSHardener() *OSHardener { return &OSHardener{} }

// Name returns "os".
func (o *OSHardener) Name() string { return "os" }

// CanFix always returns false — implementation pending.
func (o *OSHardener) CanFix(_ scanner.Finding) bool { return false }

// Preview returns an empty FixPlan.
func (o *OSHardener) Preview(f scanner.Finding) FixPlan { return FixPlan{Finding: f} }

// Apply is a no-op stub.
func (o *OSHardener) Apply(_ context.Context, _ FixPlan) error { return nil }

// Verify is a no-op stub.
func (o *OSHardener) Verify(_ context.Context, _ FixPlan) error { return nil }

// Rollback is a no-op stub.
func (o *OSHardener) Rollback(_ context.Context, _ FixPlan) error { return nil }
