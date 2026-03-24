# Defense-Kit v2 Phase 4: HTML Reporter + Alerts

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HTML dashboard report generation and alert notifications (Slack webhook, email SMTP, generic webhook with HMAC signing) to the reporting pipeline.

**Architecture:** HTML reporter uses Go html/template with static CSS (no JavaScript). Alert system supports multiple channels with configurable severity thresholds. Webhook payloads signed with HMAC-SHA256. Evidence redacted in alerts.

**Tech Stack:** Go html/template, net/http (webhooks), net/smtp (email), crypto/hmac

**Spec:** `docs/superpowers/specs/2026-03-21-defense-kit-v2-design.md` (Sections 8, 24, 25)

---

## File Map

```
defense-kit-cli/
├── internal/
│   └── reporter/
│       ├── terminal.go        # (existing)
│       ├── json.go            # (existing)
│       ├── html.go            # NEW: HTML dashboard
│       ├── alert.go           # NEW: Alert dispatcher
│       ├── slack.go           # NEW: Slack webhook
│       ├── email.go           # NEW: Email SMTP
│       ├── webhook.go         # NEW: Generic webhook + HMAC
│       ├── html_test.go       # NEW
│       ├── alert_test.go      # NEW
│       └── reporter_test.go   # (existing)
├── templates/
│   └── report.html            # HTML template
└── cmd/defense-kit/
    └── main.go                # Add --html and --alert flags
```

---

### Task 1: HTML Reporter

**Files:**
- Create: `defense-kit-cli/internal/reporter/html.go`
- Create: `defense-kit-cli/internal/reporter/html_test.go`
- Create: `defense-kit-cli/templates/report.html`

- [ ] **Step 1: Write failing test**

Test: HTMLReporter.Generate creates an HTML file. Verify it contains: finding titles, severity counts, "defense-kit" header, HTML-escaped evidence (no XSS), warning header about sharing.

- [ ] **Step 2: Create report.html template**

Static HTML + CSS template. No JavaScript. Must include:
- Header: "Defense-Kit Security Report" + hostname + timestamp
- Warning: "Contains security findings — do not share publicly"
- Summary bar: critical/high/medium/low counts with color coding
- Findings table: severity, scanner, title, location, evidence, remediation
- All evidence HTML-escaped via template pipeline
- Responsive CSS, dark theme, monospace for evidence

- [ ] **Step 3: Implement html.go**

```go
type HTMLReporter struct {
    templateDir string
}

func NewHTMLReporter(templateDir string) *HTMLReporter
func (h *HTMLReporter) Generate(results []scanner.ScanResult, host string, outputPath string) error
```

- Load template from templateDir/report.html (or embedded default)
- Build template data struct with findings, summary counts, metadata
- Execute template to file
- All evidence strings HTML-escaped automatically by html/template

- [ ] **Step 4: Run tests — pass**

- [ ] **Step 5: Commit**

---

### Task 2: Alert System — Dispatcher + Alerter Interface

**Files:**
- Create: `defense-kit-cli/internal/reporter/alert.go`
- Create: `defense-kit-cli/internal/reporter/alert_test.go`

- [ ] **Step 1: Write failing test**

Test: AlertDispatcher sends alerts to registered channels. Filter by min severity.

- [ ] **Step 2: Implement alert.go**

```go
// Alerter sends notifications for findings.
type Alerter interface {
    Name() string
    Send(ctx context.Context, report AlertReport) error
}

// AlertReport is the payload sent to alerters.
type AlertReport struct {
    Host      string
    ScanID    string
    Time      time.Time
    Summary   SeveritySummary
    Findings  []scanner.Finding  // filtered by min severity, evidence redacted
}

// AlertDispatcher routes alerts to configured channels.
type AlertDispatcher struct {
    alerters []alerterWithConfig
}

type alerterWithConfig struct {
    alerter     Alerter
    minSeverity scanner.Severity
}

func NewAlertDispatcher() *AlertDispatcher
func (d *AlertDispatcher) Add(a Alerter, minSeverity scanner.Severity)
func (d *AlertDispatcher) Dispatch(ctx context.Context, results []scanner.ScanResult, host, scanID string) error
```

Dispatch:
- Collect all findings from results
- For each alerter: filter findings to >= minSeverity
- Redact evidence (truncate to 100 chars, replace potential secrets with [REDACTED])
- Call alerter.Send with filtered report

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 3: Slack Webhook Alerter

**Files:**
- Create: `defense-kit-cli/internal/reporter/slack.go`
- Modify: `defense-kit-cli/internal/reporter/alert_test.go`

- [ ] **Step 1: Write test with httptest server**

Mock a Slack webhook endpoint, verify payload format.

- [ ] **Step 2: Implement slack.go**

```go
type SlackAlerter struct {
    webhookURL string
    client     *http.Client
}

func NewSlackAlerter(webhookURL string) *SlackAlerter
func (s *SlackAlerter) Name() string { return "slack" }
func (s *SlackAlerter) Send(ctx context.Context, report AlertReport) error
```

Send: POST JSON to webhook URL with Slack Block Kit format:
- Header block: "Defense-Kit Alert: {host}"
- Section: summary counts
- Section per finding (max 10): severity + title + location

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 4: Generic Webhook Alerter with HMAC

**Files:**
- Create: `defense-kit-cli/internal/reporter/webhook.go`
- Modify: `defense-kit-cli/internal/reporter/alert_test.go`

- [ ] **Step 1: Write test**

Test: webhook sends JSON payload with HMAC-SHA256 signature in X-Defense-Kit-Signature header.

- [ ] **Step 2: Implement webhook.go**

```go
type WebhookAlerter struct {
    url        string
    hmacSecret string
    requireTLS bool
    client     *http.Client
}

func NewWebhookAlerter(url, hmacSecret string, requireTLS bool) *WebhookAlerter
func (w *WebhookAlerter) Name() string { return "webhook" }
func (w *WebhookAlerter) Send(ctx context.Context, report AlertReport) error
```

Send:
- Marshal report as JSON
- Compute HMAC-SHA256 of body using hmacSecret
- Set X-Defense-Kit-Signature header: `sha256={hex}`
- POST to URL
- If requireTLS and URL not https → error

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 5: Email Alerter

**Files:**
- Create: `defense-kit-cli/internal/reporter/email.go`
- Modify: `defense-kit-cli/internal/reporter/alert_test.go`

- [ ] **Step 1: Write test**

Test: email alerter formats message correctly (subject, body, headers).

- [ ] **Step 2: Implement email.go**

```go
type EmailAlerter struct {
    to       string
    from     string
    smtpHost string
    smtpPort string
}

func NewEmailAlerter(to, from, smtpHost, smtpPort string) *EmailAlerter
func (e *EmailAlerter) Name() string { return "email" }
func (e *EmailAlerter) Send(ctx context.Context, report AlertReport) error
```

- Subject: "Defense-Kit Alert: {summary.Total} findings on {host}"
- Body: plain text summary + finding list
- Use net/smtp.SendMail

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Commit**

---

### Task 6: Wire to CLI

**Files:**
- Modify: `defense-kit-cli/cmd/defense-kit/main.go`

- [ ] **Step 1: Add flags to scan command**

```
--html string    generate HTML report at path
--alert          send alerts via configured channels
```

- [ ] **Step 2: Wire HTML generation in runScan**

After JSON report, if `--html` flag provided:
```go
if htmlPath != "" {
    hr := reporter.NewHTMLReporter(templateDir)
    hr.Generate(results, hostname, htmlPath)
}
```

- [ ] **Step 3: Wire alerts in runScan**

If `--alert` flag, read alert config from config.yml, create dispatcher, add configured alerters, dispatch.

- [ ] **Step 4: Add report command**

```
defense-kit report --html output.html  # regenerate from last scan JSON
```

- [ ] **Step 5: Build and test**

- [ ] **Step 6: Commit**

---

### Task 7: E2E Verification

- [ ] **Step 1:** `./bin/defense-kit scan --category environment --html /tmp/report.html` → verify HTML file created
- [ ] **Step 2:** Open HTML file, verify it renders correctly
- [ ] **Step 3:** `go test ./... -race` → all pass
- [ ] **Step 4:** Final commit
