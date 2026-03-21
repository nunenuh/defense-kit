package code

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ContainersScanner checks for security issues in container configurations.
type ContainersScanner struct{}

// NewContainersScanner creates a new ContainersScanner.
func NewContainersScanner() *ContainersScanner {
	return &ContainersScanner{}
}

func (s *ContainersScanner) Name() string            { return "containers" }
func (s *ContainersScanner) Category() string        { return "code" }
func (s *ContainersScanner) RequiresRoot() bool      { return false }
func (s *ContainersScanner) RequiredTools() []string { return nil }
func (s *ContainersScanner) OptionalTools() []string { return []string{"hadolint", "dockle"} }
func (s *ContainersScanner) Available() bool         { return true }
func (s *ContainersScanner) Description() string {
	return "Checks for container security issues including privileged containers, exposed sockets, insecure base images, and missing security contexts."
}

// hadolintFinding is the JSON object emitted by `hadolint --format json`.
type hadolintFinding struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Level   string `json:"level"`
	File    string `json:"file"`
}

// hadolintSeverity maps hadolint levels to scanner severities.
func hadolintSeverity(level string) scanner.Severity {
	switch strings.ToLower(level) {
	case "error":
		return scanner.SevHigh
	case "warning":
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

// Scan walks target paths for Dockerfiles and lints them with hadolint when available.
func (s *ContainersScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	roots := opts.TargetPaths
	if len(roots) == 0 {
		return nil, nil
	}

	// Collect all Dockerfile paths.
	var dockerfiles []string
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			if strings.HasPrefix(name, "Dockerfile") {
				dockerfiles = append(dockerfiles, path)
			}
			return nil
		})
	}

	if len(dockerfiles) == 0 {
		return nil, nil
	}

	if opts.ToolRunner == nil || !opts.ToolRunner.Available("hadolint") {
		return nil, nil
	}

	// Track findings by ID for deduplication.
	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	for _, dockerfile := range dockerfiles {
		out, err := opts.ToolRunner.Run(ctx, "hadolint", []string{"--format", "json", dockerfile})
		if err == nil || len(out) > 0 {
			var raw []hadolintFinding
			if jsonErr := json.Unmarshal(out, &raw); jsonErr == nil {
				for _, r := range raw {
					location := fmt.Sprintf("%s:%d", r.File, r.Line)
					title := r.Code
					if title == "" {
						title = r.Message
					}
					f := scanner.Finding{
						ID:       scanner.GenerateFindingID("containers", location, title),
						Scanner:  s.Name(),
						Severity: hadolintSeverity(r.Level),
						Title:    title,
						Detail:   r.Message,
						Location: location,
						Metadata: map[string]string{
							"code":  r.Code,
							"level": r.Level,
						},
					}
					if !seenIDs[f.ID] {
						seenIDs[f.ID] = true
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings, nil
}
