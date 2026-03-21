package environment

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// EnvVarsScanner checks the current process environment variables for
// suspicious or dangerous values.
type EnvVarsScanner struct{}

// NewEnvVarsScanner creates a new EnvVarsScanner.
func NewEnvVarsScanner() *EnvVarsScanner {
	return &EnvVarsScanner{}
}

func (s *EnvVarsScanner) Name() string           { return "env_vars" }
func (s *EnvVarsScanner) Category() string       { return "environment" }
func (s *EnvVarsScanner) RequiresRoot() bool     { return false }
func (s *EnvVarsScanner) RequiredTools() []string { return nil }
func (s *EnvVarsScanner) OptionalTools() []string { return nil }
func (s *EnvVarsScanner) Available() bool        { return true }
func (s *EnvVarsScanner) Description() string {
	return "Checks current environment variables for dangerous values: PATH manipulation, LD_PRELOAD injection, PROMPT_COMMAND exfiltration, and suspicious proxy settings."
}

// Scan inspects the running environment for dangerous variable values.
func (s *EnvVarsScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// --- PATH checks ---
	pathVal := os.Getenv("PATH")
	if pathVal != "" {
		entries := strings.Split(pathVal, ":")
		for _, entry := range entries {
			lower := strings.ToLower(entry)
			if strings.Contains(lower, "/tmp") || strings.Contains(lower, "/dev/shm") {
				loc := "env:PATH"
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", loc, "PATH contains writable directory"),
					Scanner:     "env_vars",
					Severity:    scanner.SevHigh,
					Title:       "PATH contains writable directory",
					Detail:      fmt.Sprintf("PATH entry %q points to a world-writable location, enabling binary hijacking.", entry),
					Evidence:    fmt.Sprintf("PATH=%s", pathVal),
					Location:    loc,
					Remediation: "Remove /tmp and /dev/shm entries from your PATH.",
				})
			}
		}

		// Check for "." or empty entry (allows CWD execution).
		for _, entry := range entries {
			if entry == "." || entry == "" {
				loc := "env:PATH"
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", loc, "PATH contains current directory"),
					Scanner:     "env_vars",
					Severity:    scanner.SevHigh,
					Title:       "PATH contains current directory or empty entry",
					Detail:      "An empty string or '.' in PATH causes binaries in the current directory to be executed, enabling hijacking attacks.",
					Evidence:    fmt.Sprintf("PATH=%s", pathVal),
					Location:    loc,
					Remediation: "Remove '.' and empty entries from PATH.",
				})
				break
			}
		}
	}

	// --- LD_PRELOAD check ---
	ldPreload := os.Getenv("LD_PRELOAD")
	if ldPreload != "" {
		loc := "env:LD_PRELOAD"
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("env_vars", loc, "LD_PRELOAD is set"),
			Scanner:     "env_vars",
			Severity:    scanner.SevCritical,
			Title:       "LD_PRELOAD is set",
			Detail:      "LD_PRELOAD allows injecting arbitrary shared libraries into every process, which is a common rootkit technique.",
			Evidence:    fmt.Sprintf("LD_PRELOAD=%s", ldPreload),
			Location:    loc,
			Remediation: "Unset LD_PRELOAD unless explicitly required by a trusted application.",
		})
	}

	// --- LD_LIBRARY_PATH check ---
	ldLibPath := os.Getenv("LD_LIBRARY_PATH")
	if ldLibPath != "" {
		suspectDirs := []string{"/tmp", "/dev/shm", "/home"}
		for _, suspect := range suspectDirs {
			if strings.Contains(ldLibPath, suspect) {
				loc := "env:LD_LIBRARY_PATH"
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", loc, "LD_LIBRARY_PATH contains suspicious path"),
					Scanner:     "env_vars",
					Severity:    scanner.SevHigh,
					Title:       "LD_LIBRARY_PATH contains suspicious path",
					Detail:      fmt.Sprintf("LD_LIBRARY_PATH contains %q, which may allow loading malicious shared libraries.", suspect),
					Evidence:    fmt.Sprintf("LD_LIBRARY_PATH=%s", ldLibPath),
					Location:    loc,
					Remediation: "Remove suspicious directories from LD_LIBRARY_PATH.",
				})
				break
			}
		}
	}

	// --- PROMPT_COMMAND check ---
	promptCmd := os.Getenv("PROMPT_COMMAND")
	if promptCmd != "" {
		lowerPC := strings.ToLower(promptCmd)
		for _, tool := range []string{"curl", "wget", "nc", "base64"} {
			if strings.Contains(lowerPC, tool) {
				loc := "env:PROMPT_COMMAND"
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("env_vars", loc, "PROMPT_COMMAND contains network/encoding tool"),
					Scanner:     "env_vars",
					Severity:    scanner.SevCritical,
					Title:       "PROMPT_COMMAND contains network/encoding tool",
					Detail:      fmt.Sprintf("PROMPT_COMMAND contains %q, which may silently exfiltrate data or execute malicious code on every prompt.", tool),
					Evidence:    fmt.Sprintf("PROMPT_COMMAND=%s", promptCmd),
					Location:    loc,
					Remediation: "Remove curl, wget, nc, and base64 from PROMPT_COMMAND.",
				})
				break
			}
		}
	}

	// --- HTTP proxy checks ---
	for _, proxyVar := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		proxyVal := os.Getenv(proxyVar)
		if proxyVal == "" {
			continue
		}
		lower := strings.ToLower(proxyVal)
		// Only flag non-localhost proxies.
		if !strings.Contains(lower, "localhost") && !strings.Contains(lower, "127.0.0.1") && !strings.Contains(lower, "::1") {
			loc := fmt.Sprintf("env:%s", proxyVar)
			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("env_vars", loc, "Non-localhost proxy configured"),
				Scanner:     "env_vars",
				Severity:    scanner.SevMedium,
				Title:       "Non-localhost proxy configured",
				Detail:      fmt.Sprintf("%s is set to %q, routing all HTTP traffic through a remote proxy.", proxyVar, proxyVal),
				Evidence:    fmt.Sprintf("%s=%s", proxyVar, proxyVal),
				Location:    loc,
				Remediation: "Verify the proxy setting is intentional and the proxy server is trusted.",
			})
		}
	}

	return findings, nil
}
