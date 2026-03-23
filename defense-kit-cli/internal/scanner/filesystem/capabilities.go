package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// capabilityRule maps a Linux capability string to its severity and detail.
type capabilityRule struct {
	severity    scanner.Severity
	title       string
	detail      string
	remediation string
}

// capabilityRules defines which capabilities are dangerous and at what severity.
var capabilityRules = map[string]capabilityRule{
	"cap_setuid": {
		severity:    scanner.SevCritical,
		title:       "Binary has cap_setuid capability",
		detail:      "cap_setuid allows a binary to change its UID to any user, including root. This is equivalent to having the SUID bit and can be exploited for privilege escalation.",
		remediation: "Remove the capability with `setcap -r <binary>` unless it is explicitly required. Prefer dropping the capability after use in application code.",
	},
	"cap_sys_admin": {
		severity:    scanner.SevCritical,
		title:       "Binary has cap_sys_admin capability",
		detail:      "cap_sys_admin is one of the most powerful Linux capabilities, enabling a wide range of privileged operations (mount, namespace, device access). A binary with this capability can escalate privileges in many ways.",
		remediation: "Remove cap_sys_admin with `setcap -r <binary>`. Only assign it if absolutely necessary and only to well-audited binaries.",
	},
	"cap_net_raw": {
		severity:    scanner.SevHigh,
		title:       "Binary has cap_net_raw capability",
		detail:      "cap_net_raw allows sending raw IP packets and binding to any network address, which can be used for network sniffing or spoofing.",
		remediation: "Remove cap_net_raw with `setcap -r <binary>` unless required (e.g., ping). Consider using a socket activation service instead.",
	},
	"cap_net_admin": {
		severity:    scanner.SevHigh,
		title:       "Binary has cap_net_admin capability",
		detail:      "cap_net_admin allows various network administration tasks including modifying routing tables, firewall rules, and interface configuration.",
		remediation: "Remove cap_net_admin with `setcap -r <binary>` unless the binary is a trusted network management tool.",
	},
}

// suspiciousCapPaths are filesystem path prefixes where any capability is critical.
var suspiciousCapPaths = []string{
	"/tmp/",
	"/home/",
}

// defaultGetcapPaths are the directories searched by default.
var defaultGetcapPaths = []string{
	"/usr/bin",
	"/usr/sbin",
	"/bin",
	"/sbin",
}

// CapabilitiesScanner checks for binaries with elevated Linux capabilities
// that could be used for privilege escalation.
type CapabilitiesScanner struct{}

// NewCapabilitiesScanner creates a new CapabilitiesScanner.
func NewCapabilitiesScanner() *CapabilitiesScanner {
	return &CapabilitiesScanner{}
}

func (s *CapabilitiesScanner) Name() string            { return "capabilities" }
func (s *CapabilitiesScanner) Category() string        { return "filesystem" }
func (s *CapabilitiesScanner) RequiresRoot() bool      { return true }
func (s *CapabilitiesScanner) RequiredTools() []string { return nil }
func (s *CapabilitiesScanner) OptionalTools() []string { return []string{"getcap"} }
func (s *CapabilitiesScanner) Available() bool         { return true }
func (s *CapabilitiesScanner) Description() string {
	return "Checks for binaries with elevated Linux capabilities (e.g., CAP_NET_RAW, CAP_SYS_PTRACE) that could be used for privilege escalation."
}

// Scan runs getcap against standard system binary directories and flags
// dangerous capabilities.
func (s *CapabilitiesScanner) Scan(_ context.Context, _ scanner.ScanOptions) ([]scanner.Finding, error) {
	getcapPath, err := exec.LookPath("getcap")
	if err != nil {
		// getcap not available — skip gracefully.
		return nil, nil
	}

	// Run getcap with -r (recursive) on all standard paths in one invocation.
	cmdArgs := append([]string{"-r"}, defaultGetcapPaths...)
	cmd := exec.Command(getcapPath, cmdArgs...)
	out, err := cmd.Output()
	// getcap returns non-zero on partial failures (e.g., permission denied on
	// individual files); use the output that was produced regardless.
	if err != nil && len(out) == 0 {
		return nil, nil
	}

	return parseGetcapOutput(string(out)), nil
}

// ParseGetcapOutput parses the output of `getcap -r` and returns findings.
// Exported for testing with synthetic input.
func ParseGetcapOutput(output string) []scanner.Finding {
	return parseGetcapOutput(output)
}

// parseGetcapOutput parses the output of `getcap -r` and returns findings.
// Each output line has the form:
//
//	/path/to/binary cap_net_raw=ep
func parseGetcapOutput(output string) []scanner.Finding {
	var findings []scanner.Finding
	seen := make(map[string]bool)

	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		binaryPath, caps := splitGetcapLine(line)
		if binaryPath == "" || caps == "" {
			continue
		}

		// Check if this binary is in a suspicious path — any capability is CRITICAL.
		inSuspiciousPath := false
		for _, prefix := range suspiciousCapPaths {
			if strings.HasPrefix(binaryPath, prefix) {
				inSuspiciousPath = true
				break
			}
		}

		if inSuspiciousPath {
			key := binaryPath + ":suspicious_path"
			if !seen[key] {
				seen[key] = true
				findings = append(findings, scanner.Finding{
					ID:          scanner.GenerateFindingID("capabilities", binaryPath, "Capability on binary in suspicious path"),
					Scanner:     "capabilities",
					Severity:    scanner.SevCritical,
					Title:       "Capability assigned to binary in suspicious path",
					Detail:      fmt.Sprintf("Binary %q in a world-writable or user-controlled directory has Linux capabilities assigned (%s). This is a strong indicator of privilege escalation staging.", binaryPath, caps),
					Evidence:    line,
					Location:    binaryPath,
					Remediation: fmt.Sprintf("Remove the capability immediately: `setcap -r %q`. Investigate how this file was placed in a suspicious directory.", binaryPath),
				})
			}
			continue
		}

		// Check each capability token against the rules.
		capTokens := strings.Split(caps, ",")
		for _, token := range capTokens {
			// Normalise: strip the permission suffix (=ep, +ep, etc.) and lowercase.
			capName := strings.ToLower(strings.FieldsFunc(token, func(r rune) bool {
				return r == '=' || r == '+' || r == '-'
			})[0])

			rule, known := capabilityRules[capName]
			if !known {
				continue
			}

			key := binaryPath + ":" + capName
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, scanner.Finding{
				ID:          scanner.GenerateFindingID("capabilities", binaryPath, rule.title),
				Scanner:     "capabilities",
				Severity:    rule.severity,
				Title:       rule.title,
				Detail:      fmt.Sprintf("%s Found on binary: %s", rule.detail, binaryPath),
				Evidence:    line,
				Location:    binaryPath,
				Remediation: rule.remediation,
				References: []string{
					"https://man7.org/linux/man-pages/man7/capabilities.7.html",
				},
			})
		}
	}

	return findings
}

// splitGetcapLine splits a getcap output line into binary path and capabilities string.
// Example input: "/usr/bin/ping cap_net_raw=ep"
func splitGetcapLine(line string) (binaryPath, caps string) {
	// The binary path is the first space-delimited token; the rest is capabilities.
	// However, paths can contain spaces on some systems, so we split at the last
	// space-separated capabilities token that contains "=", "+", or "-".
	// Simplest heuristic: split on the last space before the capabilities field.
	idx := strings.LastIndex(line, " ")
	if idx < 0 {
		return "", ""
	}
	binaryPath = strings.TrimSpace(line[:idx])
	caps = strings.TrimSpace(line[idx+1:])
	if binaryPath == "" || caps == "" {
		return "", ""
	}
	return binaryPath, caps
}
