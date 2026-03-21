package auth

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// UsersScanner audits local user accounts for dangerous configuration.
type UsersScanner struct{}

// NewUsersScanner creates a new UsersScanner.
func NewUsersScanner() *UsersScanner {
	return &UsersScanner{}
}

func (s *UsersScanner) Name() string            { return "users" }
func (s *UsersScanner) Category() string        { return "auth" }
func (s *UsersScanner) RequiresRoot() bool      { return true }
func (s *UsersScanner) RequiredTools() []string { return nil }
func (s *UsersScanner) OptionalTools() []string { return nil }
func (s *UsersScanner) Available() bool         { return true }
func (s *UsersScanner) Description() string {
	return "Audits local user accounts for dangerous configuration such as UID 0 accounts, passwordless users, and stale accounts."
}

// Scan is a stub implementation — returns no findings.
func (s *UsersScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	return nil, nil
}
