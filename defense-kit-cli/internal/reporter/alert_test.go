package reporter_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// --- helpers ---

func makeAlertFinding(sev scanner.Severity, title, evidence string) scanner.Finding {
	return scanner.Finding{
		ID:          "alert-test-id",
		Scanner:     "test-scanner",
		Severity:    sev,
		Title:       title,
		Detail:      "detail text",
		Evidence:    evidence,
		Location:    "/some/location",
		Remediation: "fix it",
	}
}

func makeAlertResults(findings ...scanner.Finding) []scanner.ScanResult {
	return []scanner.ScanResult{
		{
			Scanner:  "test-scanner",
			Status:   scanner.ScanSuccess,
			Findings: findings,
		},
	}
}

// captureAlerter records the AlertReport it receives.
type captureAlerter struct {
	name    string
	reports []reporter.AlertReport
}

func (c *captureAlerter) Name() string { return c.name }
func (c *captureAlerter) Send(_ context.Context, r reporter.AlertReport) error {
	c.reports = append(c.reports, r)
	return nil
}

// --- AlertDispatcher tests ---

func TestAlertDispatcher_FiltersMinSeverity(t *testing.T) {
	cap := &captureAlerter{name: "capture"}
	d := reporter.NewAlertDispatcher()
	d.Add(cap, scanner.SevHigh)

	findings := []scanner.Finding{
		makeAlertFinding(scanner.SevLow, "Low Finding", "low evidence"),
		makeAlertFinding(scanner.SevMedium, "Medium Finding", "medium evidence"),
		makeAlertFinding(scanner.SevHigh, "High Finding", "high evidence"),
		makeAlertFinding(scanner.SevCritical, "Critical Finding", "critical evidence"),
	}
	results := makeAlertResults(findings...)

	err := d.Dispatch(context.Background(), results, "testhost", "dk-scan-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cap.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(cap.reports))
	}

	report := cap.reports[0]
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings (HIGH+CRITICAL), got %d", len(report.Findings))
	}

	for _, f := range report.Findings {
		if f.Severity < scanner.SevHigh {
			t.Errorf("expected only HIGH+ findings, got severity %v", f.Severity)
		}
	}
}

func TestAlertDispatcher_RedactsEvidence(t *testing.T) {
	cap := &captureAlerter{name: "capture"}
	d := reporter.NewAlertDispatcher()
	d.Add(cap, scanner.SevLow)

	longEvidence := strings.Repeat("X", 200)
	findings := []scanner.Finding{
		makeAlertFinding(scanner.SevHigh, "Finding With Long Evidence", longEvidence),
	}
	results := makeAlertResults(findings...)

	err := d.Dispatch(context.Background(), results, "testhost", "dk-scan-002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cap.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(cap.reports))
	}

	for _, f := range cap.reports[0].Findings {
		if len(f.Evidence) > 100 {
			t.Errorf("expected evidence truncated to 100 chars, got %d chars", len(f.Evidence))
		}
	}
}

func TestAlertDispatcher_HostAndScanIDSet(t *testing.T) {
	cap := &captureAlerter{name: "capture"}
	d := reporter.NewAlertDispatcher()
	d.Add(cap, scanner.SevLow)

	results := makeAlertResults(makeAlertFinding(scanner.SevLow, "Some Finding", "evidence"))

	err := d.Dispatch(context.Background(), results, "myhost.local", "dk-abc-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report := cap.reports[0]
	if report.Host != "myhost.local" {
		t.Errorf("expected host 'myhost.local', got %q", report.Host)
	}
	if report.ScanID != "dk-abc-123" {
		t.Errorf("expected scanID 'dk-abc-123', got %q", report.ScanID)
	}
	if report.Time.IsZero() {
		t.Error("expected non-zero time in report")
	}
}

func TestAlertDispatcher_NoAlertWhenNoMatchingFindings(t *testing.T) {
	cap := &captureAlerter{name: "capture"}
	d := reporter.NewAlertDispatcher()
	d.Add(cap, scanner.SevCritical)

	findings := []scanner.Finding{
		makeAlertFinding(scanner.SevLow, "Low Finding", "ev"),
		makeAlertFinding(scanner.SevMedium, "Medium Finding", "ev"),
	}
	results := makeAlertResults(findings...)

	err := d.Dispatch(context.Background(), results, "testhost", "dk-scan-003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Alerter should still be called but with 0 findings
	if len(cap.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(cap.reports))
	}
	if len(cap.reports[0].Findings) != 0 {
		t.Errorf("expected 0 findings in report, got %d", len(cap.reports[0].Findings))
	}
}

// --- SlackAlerter tests ---

func TestSlackAlerter_SendsPayload(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := reporter.NewSlackAlerter(srv.URL)

	report := reporter.AlertReport{
		Host:   "testhost",
		ScanID: "dk-001",
		Time:   time.Now(),
		Summary: reporter.SeveritySummary{
			Critical: 1,
			High:     2,
			Total:    3,
		},
		Findings: []scanner.Finding{
			makeAlertFinding(scanner.SevCritical, "Root SSH Enabled", "evidence"),
		},
	}

	err := a.Send(context.Background(), report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("expected non-empty POST body")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("expected valid JSON payload, got error: %v", err)
	}

	blocks, ok := payload["blocks"]
	if !ok {
		t.Fatal("expected 'blocks' key in Slack payload")
	}

	blockList, ok := blocks.([]interface{})
	if !ok || len(blockList) == 0 {
		t.Fatal("expected non-empty blocks array")
	}
}

func TestSlackAlerter_PayloadContainsHostname(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := reporter.NewSlackAlerter(srv.URL)
	report := reporter.AlertReport{
		Host:   "special-host.example.com",
		ScanID: "dk-002",
		Time:   time.Now(),
	}

	_ = a.Send(context.Background(), report)

	if !strings.Contains(string(received), "special-host.example.com") {
		t.Errorf("expected payload to contain hostname, got: %s", string(received))
	}
}

// --- WebhookAlerter tests ---

func TestWebhookAlerter_SendsHMAC(t *testing.T) {
	var sigHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get("X-Defense-Kit-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := reporter.NewWebhookAlerter(srv.URL, "my-secret", false)
	report := reporter.AlertReport{
		Host:   "testhost",
		ScanID: "dk-003",
		Time:   time.Now(),
	}

	err := a.Send(context.Background(), report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sigHeader == "" {
		t.Fatal("expected X-Defense-Kit-Signature header to be set")
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Errorf("expected signature to start with 'sha256=', got %q", sigHeader)
	}
}

func TestWebhookAlerter_RequiresTLS(t *testing.T) {
	a := reporter.NewWebhookAlerter("http://example.com/hook", "secret", true)
	report := reporter.AlertReport{
		Host:   "testhost",
		ScanID: "dk-004",
		Time:   time.Now(),
	}

	err := a.Send(context.Background(), report)
	if err == nil {
		t.Fatal("expected error when requireTLS=true and URL is http://")
	}
}

func TestWebhookAlerter_AllowsHTTPSWithRequireTLS(t *testing.T) {
	// httptest TLS server uses https
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use a client that trusts the test server's cert
	a := reporter.NewWebhookAlerterWithClient(srv.URL, "secret", true, srv.Client())

	report := reporter.AlertReport{
		Host:   "testhost",
		ScanID: "dk-005",
		Time:   time.Now(),
	}

	err := a.Send(context.Background(), report)
	if err != nil {
		t.Fatalf("unexpected error with https URL and requireTLS=true: %v", err)
	}
}

func TestWebhookAlerter_ComputesCorrectHMAC(t *testing.T) {
	var receivedBody []byte
	var sigHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		sigHeader = r.Header.Get("X-Defense-Kit-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := "super-secret-hmac-key"
	a := reporter.NewWebhookAlerter(srv.URL, secret, false)

	report := reporter.AlertReport{
		Host:   "testhost",
		ScanID: "dk-006",
		Time:   time.Now(),
	}

	err := a.Send(context.Background(), report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute the expected HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if sigHeader != expectedSig {
		t.Errorf("HMAC mismatch:\n  expected: %s\n  got:      %s", expectedSig, sigHeader)
	}
}

func TestWebhookAlerter_SetsContentType(t *testing.T) {
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := reporter.NewWebhookAlerter(srv.URL, "", false)
	report := reporter.AlertReport{Host: "testhost", ScanID: "dk-007", Time: time.Now()}

	_ = a.Send(context.Background(), report)

	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}

// --- EmailAlerter tests ---

func TestEmailAlerter_FormatsBody(t *testing.T) {
	a := reporter.NewEmailAlerter("to@example.com", "from@defense-kit.local", "smtp.example.com", "587")

	report := reporter.AlertReport{
		Host:   "prodhost",
		ScanID: "dk-email-001",
		Time:   time.Now(),
		Summary: reporter.SeveritySummary{
			Critical: 2,
			High:     1,
			Medium:   3,
			Low:      0,
			Total:    6,
		},
		Findings: []scanner.Finding{
			makeAlertFinding(scanner.SevCritical, "Critical Finding One", "evidence1"),
			makeAlertFinding(scanner.SevCritical, "Critical Finding Two", "evidence2"),
			makeAlertFinding(scanner.SevHigh, "High Finding One", "evidence3"),
			makeAlertFinding(scanner.SevMedium, "Medium Finding One", "ev4"),
			makeAlertFinding(scanner.SevMedium, "Medium Finding Two", "ev5"),
			makeAlertFinding(scanner.SevMedium, "Medium Finding Three", "ev6"),
		},
	}

	subject, body := a.FormatEmailMessage(report)

	if !strings.Contains(subject, "6") {
		t.Errorf("expected subject to contain finding count '6', got %q", subject)
	}
	if !strings.Contains(subject, "prodhost") {
		t.Errorf("expected subject to contain hostname 'prodhost', got %q", subject)
	}

	if !strings.Contains(body, "CRITICAL: 2") {
		t.Errorf("expected body to contain 'CRITICAL: 2', got:\n%s", body)
	}
	if !strings.Contains(body, "HIGH: 1") {
		t.Errorf("expected body to contain 'HIGH: 1', got:\n%s", body)
	}
	if !strings.Contains(body, "MEDIUM: 3") {
		t.Errorf("expected body to contain 'MEDIUM: 3', got:\n%s", body)
	}
	if !strings.Contains(body, "Critical Finding One") {
		t.Errorf("expected body to contain finding title, got:\n%s", body)
	}
}

func TestEmailAlerter_LimitsTo10Findings(t *testing.T) {
	a := reporter.NewEmailAlerter("to@example.com", "from@defense-kit.local", "smtp.example.com", "587")

	var findings []scanner.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, makeAlertFinding(scanner.SevHigh, "Finding", "ev"))
	}

	report := reporter.AlertReport{
		Host:     "testhost",
		ScanID:   "dk-email-002",
		Time:     time.Now(),
		Findings: findings,
	}

	_, body := a.FormatEmailMessage(report)

	// Count occurrences of "Finding" in the body — each finding title is "Finding"
	count := strings.Count(body, "[HIGH]")
	if count > 10 {
		t.Errorf("expected at most 10 findings in email body, got %d", count)
	}
}
