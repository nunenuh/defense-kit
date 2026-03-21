package code

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
)

const (
	maxFileSize    = 1 * 1024 * 1024 // 1 MB
	sniffSize      = 512
	maxEvidenceLen = 200
)

// credentialPattern describes a secret pattern to match in file content.
type credentialPattern struct {
	re          *regexp.Regexp
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

var credentialPatterns = []credentialPattern{
	{
		re:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		title:       "AWS access key exposed",
		severity:    scanner.SevCritical,
		detail:      "An AWS access key ID (AKIA…) was found in a file. This may allow unauthorized access to AWS services.",
		remediation: "Revoke the key immediately via the AWS IAM console and rotate all dependent credentials.",
	},
	{
		re:          regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*\S+`),
		title:       "AWS secret access key exposed",
		severity:    scanner.SevCritical,
		detail:      "An AWS secret access key assignment was found in a file. This may grant full programmatic access to AWS services.",
		remediation: "Revoke the key immediately via the AWS IAM console, remove it from the file, and use environment variables or a secrets manager.",
	},
	{
		re:          regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		title:       "Private key material exposed",
		severity:    scanner.SevCritical,
		detail:      "A PEM-encoded private key header was found in a file. Exposure of private key material can lead to impersonation or decryption of sensitive data.",
		remediation: "Remove the key from the file, revoke/reissue the key pair, and store private keys only in a secrets manager or hardware token.",
	},
	{
		re:          regexp.MustCompile(`(?i)(api[_-]?key|api[_-]?token|api[_-]?secret)\s*[:=]\s*['"]?\S{20,}`),
		title:       "Generic API key or token exposed",
		severity:    scanner.SevHigh,
		detail:      "A generic API key, token, or secret assignment with a long value was found. This may grant unauthorized access to an external service.",
		remediation: "Rotate the credential immediately and store it using environment variables or a dedicated secrets manager.",
	},
	{
		re:          regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?\S+`),
		title:       "Hardcoded password detected",
		severity:    scanner.SevMedium,
		detail:      "A password or passwd assignment was found in a file. Hardcoded passwords are easily extracted from source code and version control history.",
		remediation: "Remove the hardcoded password and source it from environment variables or a secrets manager at runtime.",
	},
}

// specificPaths lists file paths (relative to each target root) that are
// always included in the scan regardless of extension.
var specificPaths = []string{
	".env",
	".bash_history",
	".aws/credentials",
	".git/config",
}

// CredentialsScanner scans files for leaked secrets and credentials.
type CredentialsScanner struct{}

// NewCredentialsScanner creates a new CredentialsScanner.
func NewCredentialsScanner() *CredentialsScanner {
	return &CredentialsScanner{}
}

func (s *CredentialsScanner) Name() string           { return "credentials" }
func (s *CredentialsScanner) Category() string       { return "code" }
func (s *CredentialsScanner) RequiresRoot() bool     { return false }
func (s *CredentialsScanner) RequiredTools() []string { return nil }
func (s *CredentialsScanner) OptionalTools() []string { return []string{"gitleaks", "trufflehog"} }
func (s *CredentialsScanner) Available() bool        { return true }
func (s *CredentialsScanner) Description() string {
	return "Scans files for leaked credentials including AWS keys, private keys, API tokens, and hardcoded passwords."
}

// Scan searches target paths for credential patterns.
func (s *CredentialsScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	roots := opts.TargetPaths
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err == nil {
			roots = []string{home}
		}
	}

	// Track findings by ID for deduplication.
	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	addFindings := func(ff []scanner.Finding) {
		for _, f := range ff {
			if !seenIDs[f.ID] {
				seenIDs[f.ID] = true
				findings = append(findings, f)
			}
		}
	}

	// Try gitleaks first if ToolRunner is available.
	if opts.ToolRunner != nil && opts.ToolRunner.Available("gitleaks") {
		for _, root := range roots {
			out, err := opts.ToolRunner.Run(ctx, "gitleaks", []string{
				"detect", "--source", root,
				"--report-format", "json",
				"--no-git",
				"--exit-code", "0",
			})
			if err == nil || len(out) > 0 {
				gitleaksFindings, parseErr := tools.ParseGitleaksJSON(out)
				if parseErr == nil {
					addFindings(gitleaksFindings)
				}
			}
		}
	}

	// Always run native checks too.
	seen := make(map[string]struct{})
	var paths []string

	for _, root := range roots {
		// Collect specific well-known files relative to each root.
		for _, rel := range specificPaths {
			p := filepath.Join(root, rel)
			if _, visited := seen[p]; !visited {
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
		}

		// Walk all files under the root.
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if _, visited := seen[path]; !visited {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
			return nil
		})
	}

	for _, path := range paths {
		ff, err := scanFileForCredentials(path)
		if err != nil {
			// Unreadable or skipped — continue silently.
			continue
		}
		addFindings(ff)
	}
	return findings, nil
}

// scanFileForCredentials scans a single file and returns any credential findings.
func scanFileForCredentials(path string) ([]scanner.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}
	if info.Size() > maxFileSize {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Sniff the first 512 bytes to detect binary files.
	sniff := make([]byte, sniffSize)
	n, _ := f.Read(sniff)
	if bytes.IndexByte(sniff[:n], 0x00) >= 0 {
		// Binary file — skip.
		return nil, nil
	}

	// Rewind by reopening.
	f.Close()
	f, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding
	lineNum := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		for _, p := range credentialPatterns {
			if p.re.MatchString(line) {
				location := fmt.Sprintf("%s:%d", path, lineNum)
				evidence := strings.TrimSpace(line)
				if len(evidence) > maxEvidenceLen {
					evidence = evidence[:maxEvidenceLen]
				}
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("credentials", location, p.title),
					Scanner:     "credentials",
					Severity:    p.severity,
					Title:       p.title,
					Detail:      p.detail,
					Evidence:    evidence,
					Location:    location,
					Remediation: p.remediation,
				})
			}
		}
	}
	return findings, sc.Err()
}
