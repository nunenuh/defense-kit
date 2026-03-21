package process

import (
	"context"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ClipboardScanner checks for processes accessing the clipboard in unexpected ways.
type ClipboardScanner struct{}

// NewClipboardScanner creates a new ClipboardScanner.
func NewClipboardScanner() *ClipboardScanner {
	return &ClipboardScanner{}
}

func (s *ClipboardScanner) Name() string           { return "clipboard" }
func (s *ClipboardScanner) Category() string       { return "process" }
func (s *ClipboardScanner) RequiresRoot() bool     { return false }
func (s *ClipboardScanner) RequiredTools() []string { return nil }
func (s *ClipboardScanner) OptionalTools() []string { return nil }
func (s *ClipboardScanner) Available() bool        { return true }
func (s *ClipboardScanner) Description() string {
	return "Detects processes that are accessing or hijacking the system clipboard, which can be used to steal credentials or replace cryptocurrency addresses."
}

// Scan checks for processes with suspicious clipboard access.
func (s *ClipboardScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	// TODO: implement clipboard access detection via /proc and X11/Wayland utilities
	return nil, nil
}
