package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const slackMaxFindings = 10

// SlackAlerter delivers AlertReports to a Slack incoming webhook URL.
type SlackAlerter struct {
	webhookURL string
	client     *http.Client
}

// NewSlackAlerter returns a SlackAlerter that posts to the given Slack webhook URL.
func NewSlackAlerter(webhookURL string) *SlackAlerter {
	return &SlackAlerter{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns the identifier for this alerter.
func (s *SlackAlerter) Name() string { return "slack" }

// Send marshals the AlertReport as a Slack Block Kit payload and POSTs it to
// the configured webhook URL.
func (s *SlackAlerter) Send(ctx context.Context, report AlertReport) error {
	payload := s.buildPayload(report)

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("slack: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// slackBlock is a single Block Kit block element.
type slackBlock struct {
	Type string          `json:"type"`
	Text *slackTextBlock `json:"text,omitempty"`
}

// slackTextBlock is the text sub-element inside a Slack block.
type slackTextBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// slackPayload is the top-level Slack message payload.
type slackPayload struct {
	Blocks []slackBlock `json:"blocks"`
}

// buildPayload constructs the Slack Block Kit message from an AlertReport.
func (s *SlackAlerter) buildPayload(report AlertReport) slackPayload {
	header := slackBlock{
		Type: "header",
		Text: &slackTextBlock{
			Type: "plain_text",
			Text: fmt.Sprintf("Defense-Kit Alert: %s", report.Host),
		},
	}

	summaryText := fmt.Sprintf(
		"*Scan ID:* %s\n*Time:* %s\n*Total:* %d  |  *Critical:* %d  |  *High:* %d  |  *Medium:* %d  |  *Low:* %d",
		report.ScanID,
		report.Time.UTC().Format(time.RFC3339),
		report.Summary.Total,
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
	)
	summaryBlock := slackBlock{
		Type: "section",
		Text: &slackTextBlock{Type: "mrkdwn", Text: summaryText},
	}

	detailsBlock := slackBlock{
		Type: "section",
		Text: &slackTextBlock{Type: "mrkdwn", Text: s.buildFindingsText(report.Findings)},
	}

	return slackPayload{
		Blocks: []slackBlock{header, summaryBlock, detailsBlock},
	}
}

// buildFindingsText formats up to slackMaxFindings findings as Slack markdown.
func (s *SlackAlerter) buildFindingsText(findings []scanner.Finding) string {
	if len(findings) == 0 {
		return "_No findings at this severity level._"
	}

	limit := len(findings)
	if limit > slackMaxFindings {
		limit = slackMaxFindings
	}

	var sb strings.Builder
	sb.WriteString("*Top Findings:*\n")
	for _, f := range findings[:limit] {
		sb.WriteString(fmt.Sprintf("• `[%s]` *%s* — %s\n", f.Severity.String(), f.Title, f.Location))
	}

	if len(findings) > slackMaxFindings {
		sb.WriteString(fmt.Sprintf("_...and %d more findings._", len(findings)-slackMaxFindings))
	}

	return sb.String()
}
