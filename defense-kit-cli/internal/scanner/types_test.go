package scanner_test

import (
	"strings"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// --- GenerateFindingID tests ---

func TestGenerateFindingID_Deterministic(t *testing.T) {
	id1 := scanner.GenerateFindingID("secrets", "/etc/passwd", "Sensitive file exposed")
	id2 := scanner.GenerateFindingID("secrets", "/etc/passwd", "Sensitive file exposed")
	if id1 != id2 {
		t.Errorf("expected deterministic ID, got %q and %q", id1, id2)
	}
}

func TestGenerateFindingID_StartsWithScannerName(t *testing.T) {
	scannerName := "secrets"
	id := scanner.GenerateFindingID(scannerName, "/etc/passwd", "Sensitive file exposed")
	if !strings.HasPrefix(id, scannerName+"-") {
		t.Errorf("expected ID to start with %q-, got %q", scannerName, id)
	}
}

func TestGenerateFindingID_NotEmpty(t *testing.T) {
	id := scanner.GenerateFindingID("secrets", "/etc/passwd", "Sensitive file exposed")
	if id == "" {
		t.Error("expected non-empty ID")
	}
}

func TestGenerateFindingID_DifferentInputsDifferentIDs(t *testing.T) {
	id1 := scanner.GenerateFindingID("secrets", "/etc/passwd", "Sensitive file exposed")
	id2 := scanner.GenerateFindingID("secrets", "/tmp/other", "Different finding")
	if id1 == id2 {
		t.Errorf("expected different IDs for different inputs, both got %q", id1)
	}
}

func TestGenerateFindingID_FormatContainsHash(t *testing.T) {
	id := scanner.GenerateFindingID("net", "/proc/net/tcp", "Open port")
	// Format: {scannerName}-{sha256(location+title)[:12]}
	parts := strings.SplitN(id, "-", 2)
	if len(parts) != 2 {
		t.Fatalf("expected ID with dash separator, got %q", id)
	}
	hash := parts[1]
	if len(hash) != 12 {
		t.Errorf("expected 12-char hash suffix, got %d chars: %q", len(hash), hash)
	}
}

// --- Severity.String() tests ---

func TestSeverityString_Low(t *testing.T) {
	if got := scanner.SevLow.String(); got != "LOW" {
		t.Errorf("SevLow.String() = %q, want %q", got, "LOW")
	}
}

func TestSeverityString_Medium(t *testing.T) {
	if got := scanner.SevMedium.String(); got != "MEDIUM" {
		t.Errorf("SevMedium.String() = %q, want %q", got, "MEDIUM")
	}
}

func TestSeverityString_High(t *testing.T) {
	if got := scanner.SevHigh.String(); got != "HIGH" {
		t.Errorf("SevHigh.String() = %q, want %q", got, "HIGH")
	}
}

func TestSeverityString_Critical(t *testing.T) {
	if got := scanner.SevCritical.String(); got != "CRITICAL" {
		t.Errorf("SevCritical.String() = %q, want %q", got, "CRITICAL")
	}
}

// --- ScanStatus.String() tests ---

func TestScanStatusString_Success(t *testing.T) {
	if got := scanner.ScanSuccess.String(); got != "success" {
		t.Errorf("ScanSuccess.String() = %q, want %q", got, "success")
	}
}

func TestScanStatusString_Partial(t *testing.T) {
	if got := scanner.ScanPartial.String(); got != "partial" {
		t.Errorf("ScanPartial.String() = %q, want %q", got, "partial")
	}
}

func TestScanStatusString_Failed(t *testing.T) {
	if got := scanner.ScanFailed.String(); got != "failed" {
		t.Errorf("ScanFailed.String() = %q, want %q", got, "failed")
	}
}

func TestScanStatusString_Skipped(t *testing.T) {
	if got := scanner.ScanSkipped.String(); got != "skipped" {
		t.Errorf("ScanSkipped.String() = %q, want %q", got, "skipped")
	}
}

func TestScanStatusString_UnknownValue(t *testing.T) {
	// ScanStatus(99) is not a defined constant; should return "unknown".
	unknown := scanner.ScanStatus(99)
	if got := unknown.String(); got != "unknown" {
		t.Errorf("ScanStatus(99).String() = %q, want %q", got, "unknown")
	}
}

func TestSeverity_UnknownValue(t *testing.T) {
	// Severity(99) falls through to the default case and should return "LOW".
	unknown := scanner.Severity(99)
	if got := unknown.String(); got != "LOW" {
		t.Errorf("Severity(99).String() = %q, want %q", got, "LOW")
	}
}

func TestFindingID_EmptyInputs(t *testing.T) {
	// All-empty inputs should still produce a non-empty, deterministic ID.
	id := scanner.GenerateFindingID("", "", "")
	if id == "" {
		t.Error("GenerateFindingID with empty inputs must return a non-empty ID")
	}
	// Calling again with the same empty inputs should give the same result.
	id2 := scanner.GenerateFindingID("", "", "")
	if id != id2 {
		t.Errorf("GenerateFindingID with empty inputs is not deterministic: %q vs %q", id, id2)
	}
	// The ID format is "{scannerName}-{hash}"; with empty scanner name it starts with "-".
	if len(id) < 1 {
		t.Errorf("expected non-trivial ID even with empty inputs, got %q", id)
	}
}

func TestFindingID_LongInputs(t *testing.T) {
	// Very long scanner name, location, and title.
	longName := string(make([]byte, 1000))
	longLocation := string(make([]byte, 5000))
	longTitle := string(make([]byte, 5000))

	id := scanner.GenerateFindingID(longName, longLocation, longTitle)
	if id == "" {
		t.Error("GenerateFindingID with long inputs must return a non-empty ID")
	}

	// The hash portion is always 12 hex chars; the separator is "-".
	// Total length = len(scannerName) + 1 (dash) + 12.
	expectedLen := len(longName) + 1 + 12
	if len(id) != expectedLen {
		t.Errorf("GenerateFindingID long input: expected ID length %d, got %d", expectedLen, len(id))
	}
}
