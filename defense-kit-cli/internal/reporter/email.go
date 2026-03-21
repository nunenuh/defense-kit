package reporter

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const emailMaxFindings = 10

// EmailAlerter delivers AlertReports via SMTP email.
type EmailAlerter struct {
	to       string
	from     string
	smtpHost string
	smtpPort string
}

// NewEmailAlerter returns an EmailAlerter configured with recipient, sender,
// and SMTP server connection details.
func NewEmailAlerter(to, from, smtpHost, smtpPort string) *EmailAlerter {
	return &EmailAlerter{
		to:       to,
		from:     from,
		smtpHost: smtpHost,
		smtpPort: smtpPort,
	}
}

// Name returns the identifier for this alerter.
func (e *EmailAlerter) Name() string { return "email" }

// Send formats the AlertReport as a plain-text email and delivers it via
// net/smtp.SendMail. Authentication is not configured; extend as needed.
func (e *EmailAlerter) Send(_ context.Context, report AlertReport) error {
	subject, body := e.FormatEmailMessage(report)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		e.from, e.to, subject, body,
	)

	addr := fmt.Sprintf("%s:%s", e.smtpHost, e.smtpPort)
	if err := smtp.SendMail(addr, nil, e.from, []string{e.to}, []byte(msg)); err != nil {
		return fmt.Errorf("email: send mail: %w", err)
	}
	return nil
}

// FormatEmailMessage returns the subject line and plain-text body for an alert
// email. It is exported so that tests can verify formatting without an SMTP
// server.
func (e *EmailAlerter) FormatEmailMessage(report AlertReport) (subject, body string) {
	subject = fmt.Sprintf("Defense-Kit Alert: %d findings on %s", report.Summary.Total, report.Host)

	var sb strings.Builder

	sb.WriteString("Defense-Kit Security Alert\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	sb.WriteString(fmt.Sprintf("Host:    %s\n", report.Host))
	sb.WriteString(fmt.Sprintf("Scan ID: %s\n", report.ScanID))
	sb.WriteString(fmt.Sprintf("Time:    %s\n\n", report.Time.UTC().Format("2006-01-02 15:04:05 UTC")))

	sb.WriteString("Summary\n")
	sb.WriteString(strings.Repeat("-", 20) + "\n")
	sb.WriteString(fmt.Sprintf("CRITICAL: %d\n", report.Summary.Critical))
	sb.WriteString(fmt.Sprintf("HIGH: %d\n", report.Summary.High))
	sb.WriteString(fmt.Sprintf("MEDIUM: %d\n", report.Summary.Medium))
	sb.WriteString(fmt.Sprintf("LOW: %d\n", report.Summary.Low))
	sb.WriteString(fmt.Sprintf("TOTAL: %d\n\n", report.Summary.Total))

	limit := len(report.Findings)
	if limit > emailMaxFindings {
		limit = emailMaxFindings
	}

	if limit > 0 {
		sb.WriteString("Findings (top 10)\n")
		sb.WriteString(strings.Repeat("-", 20) + "\n")
		for i, f := range report.Findings[:limit] {
			sb.WriteString(formatFinding(i+1, f))
		}

		if len(report.Findings) > emailMaxFindings {
			sb.WriteString(fmt.Sprintf("\n...and %d more findings. Review the full report for details.\n",
				len(report.Findings)-emailMaxFindings))
		}
	}

	return subject, sb.String()
}

// formatFinding returns a single-finding block for the email body.
func formatFinding(n int, f scanner.Finding) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n%d. [%s] %s\n", n, f.Severity.String(), f.Title))
	if f.Location != "" {
		sb.WriteString(fmt.Sprintf("   Location:    %s\n", f.Location))
	}
	if f.Detail != "" {
		sb.WriteString(fmt.Sprintf("   Detail:      %s\n", f.Detail))
	}
	if f.Remediation != "" {
		sb.WriteString(fmt.Sprintf("   Remediation: %s\n", f.Remediation))
	}
	return sb.String()
}
