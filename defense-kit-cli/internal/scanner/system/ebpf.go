package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// knownGoodBPFTypes are eBPF program types that are loaded by systemd and other
// trusted system software. Programs of these types are not flagged.
var knownGoodBPFTypes = map[string]bool{
	"cgroup_skb":      true,
	"cgroup_device":   true,
	"flow_dissector":  true,
}

// EBPFScanner detects eBPF-based rootkits (BPFDoor, Symbiote, LinkPro) by
// inspecting loaded eBPF programs and raw sockets.
type EBPFScanner struct {
	procNetRawPath string
	procSysPath    string // base path for /proc/sys sysctl reads
}

// NewEBPFScanner creates a new EBPFScanner with production defaults.
func NewEBPFScanner() *EBPFScanner {
	return &EBPFScanner{
		procNetRawPath: "/proc/net/raw",
		procSysPath:    "/proc/sys",
	}
}

// newEBPFScannerWithPaths creates an EBPFScanner with injected paths for testing.
func newEBPFScannerWithPaths(procNetRawPath, procSysPath string) *EBPFScanner {
	return &EBPFScanner{
		procNetRawPath: procNetRawPath,
		procSysPath:    procSysPath,
	}
}

func (s *EBPFScanner) Name() string            { return "ebpf" }
func (s *EBPFScanner) Category() string        { return "system" }
func (s *EBPFScanner) RequiresRoot() bool      { return true }
func (s *EBPFScanner) RequiredTools() []string { return nil }
func (s *EBPFScanner) OptionalTools() []string { return []string{"bpftool"} }
func (s *EBPFScanner) Available() bool         { return true }
func (s *EBPFScanner) Description() string {
	return "Detects eBPF-based rootkits (BPFDoor, Symbiote, LinkPro) by inspecting loaded eBPF programs via bpftool, checking for raw sockets in /proc/net/raw, and auditing sysctl knobs that control eBPF security."
}

// Scan runs all eBPF detection checks and returns the findings.
func (s *EBPFScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
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

	// Check loaded eBPF programs via bpftool.
	addFindings(s.checkBPFPrograms(ctx, opts))

	// Check for raw sockets (BPFDoor indicator).
	addFindings(s.checkRawSockets())

	// Check sysctl knobs.
	addFindings(s.checkSysctlKnobs())

	return findings, nil
}

// checkBPFPrograms tries to list loaded eBPF programs via bpftool.
func (s *EBPFScanner) checkBPFPrograms(ctx context.Context, opts scanner.ScanOptions) []scanner.Finding {
	var out []byte
	var err error

	// Prefer ToolRunner if available.
	if opts.ToolRunner != nil && opts.ToolRunner.Available("bpftool") {
		out, err = opts.ToolRunner.Run(ctx, "bpftool", []string{"prog", "list"})
	} else {
		cmd := exec.CommandContext(ctx, "bpftool", "prog", "list")
		out, err = cmd.Output()
	}

	if err != nil || len(out) == 0 {
		// bpftool not available or no output — skip silently.
		return nil
	}

	return parseBPFToolOutput(out)
}

// parseBPFToolOutput parses the text output of `bpftool prog list` and flags
// suspicious program types.
func parseBPFToolOutput(data []byte) []scanner.Finding {
	var findings []scanner.Finding

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// bpftool prog list output format:
		//   <id>: <type>  name <name>  tag <tag>  gpl
		// We look for the type token after the first colon.
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[colonIdx+1:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		bpfType := strings.ToLower(fields[0])

		// Skip known-good types.
		if knownGoodBPFTypes[bpfType] {
			continue
		}

		// Extract optional program name.
		progName := ""
		for i, f := range fields {
			if f == "name" && i+1 < len(fields) {
				progName = fields[i+1]
				break
			}
		}

		loc := "bpftool prog list"

		switch bpfType {
		case "tracepoint", "kprobe", "kretprobe", "raw_tracepoint", "raw_tracepoint_writable",
			"perf_event", "lsm":
			// Could be hooking syscalls — HIGH.
			detail := fmt.Sprintf(
				"An eBPF program of type %q is loaded. Programs of this type can hook into kernel tracing infrastructure and intercept syscalls, which is a technique used by eBPF-based rootkits such as Symbiote and LinkPro.",
				bpfType,
			)
			if progName != "" {
				detail = fmt.Sprintf("eBPF program %q (type %q) is loaded. %s", progName, bpfType, "Programs of this type can hook into kernel tracing infrastructure and intercept syscalls, which is a technique used by eBPF-based rootkits such as Symbiote and LinkPro.")
			}
			id := scanner.GenerateFindingID("ebpf", loc, "suspicious bpf type: "+bpfType+" "+progName)
			findings = append(findings, scanner.Finding{
				ID:          id,
				Scanner:     "ebpf",
				Severity:    scanner.SevHigh,
				Title:       "Suspicious eBPF tracing program loaded",
				Detail:      detail,
				Evidence:    line,
				Location:    loc,
				Remediation: "Investigate the eBPF program with 'bpftool prog show id <id>'. If not associated with a legitimate tool (bcc, bpftrace, systemtap), unload it.",
			})

		case "xdp", "sched_cls", "sched_act", "tc":
			// Network filtering — could be BPFDoor.
			detail := fmt.Sprintf(
				"An eBPF program of type %q is loaded. Programs of this type attach to network interfaces and can silently filter or redirect traffic, which is how BPFDoor and similar implants operate.",
				bpfType,
			)
			if progName != "" {
				detail = fmt.Sprintf("eBPF program %q (type %q) is loaded. Programs of this type attach to network interfaces and can silently filter or redirect traffic, which is how BPFDoor and similar implants operate.", progName, bpfType)
			}
			id := scanner.GenerateFindingID("ebpf", loc, "suspicious bpf type: "+bpfType+" "+progName)
			findings = append(findings, scanner.Finding{
				ID:          id,
				Scanner:     "ebpf",
				Severity:    scanner.SevHigh,
				Title:       "Suspicious eBPF network program loaded",
				Detail:      detail,
				Evidence:    line,
				Location:    loc,
				Remediation: "Investigate the eBPF program with 'bpftool prog show id <id>'. If not associated with a legitimate networking tool, unload it and audit network traffic.",
			})
		}
	}

	return findings
}

// checkRawSockets inspects /proc/net/raw for raw socket entries. BPFDoor opens
// raw sockets to receive its activation packets.
func (s *EBPFScanner) checkRawSockets() []scanner.Finding {
	f, err := os.Open(s.procNetRawPath)
	if err != nil {
		// /proc/net/raw not readable — skip.
		return nil
	}
	defer f.Close()

	// Count non-header lines — each represents an open raw socket.
	lineCount := 0
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header line
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			lineCount++
		}
	}

	if lineCount == 0 {
		return nil
	}

	return []scanner.Finding{
		{
			ID:          scanner.GenerateFindingID("ebpf", s.procNetRawPath, "raw sockets present"),
			Scanner:     "ebpf",
			Severity:    scanner.SevMedium,
			Title:       "Raw sockets detected",
			Detail:      fmt.Sprintf("%d raw socket(s) are open. BPFDoor and similar implants use raw sockets to receive activation packets without opening a visible listening port. Verify all raw socket owners are legitimate.", lineCount),
			Evidence:    fmt.Sprintf("%d entries in %s", lineCount, s.procNetRawPath),
			Location:    s.procNetRawPath,
			Remediation: "Identify processes owning raw sockets with 'ss -a --raw -p' (requires root). Terminate any unexpected processes and investigate how they were started.",
		},
	}
}

// checkSysctlKnobs reads eBPF-relevant sysctl values directly from /proc/sys.
func (s *EBPFScanner) checkSysctlKnobs() []scanner.Finding {
	var findings []scanner.Finding

	type knob struct {
		path        string
		badValue    string
		severity    scanner.Severity
		title       string
		detail      string
		remediation string
	}

	knobs := []knob{
		{
			path:        s.procSysPath + "/kernel/unprivileged_bpf_disabled",
			badValue:    "0",
			severity:    scanner.SevMedium,
			title:       "Unprivileged eBPF is enabled",
			detail:      "kernel.unprivileged_bpf_disabled=0 allows unprivileged users to load eBPF programs, which can be exploited for privilege escalation or information disclosure.",
			remediation: "Set 'kernel.unprivileged_bpf_disabled=1' in /etc/sysctl.d/99-hardening.conf and apply with 'sysctl -p'.",
		},
		{
			path:        s.procSysPath + "/net/core/bpf_jit_harden",
			badValue:    "0",
			severity:    scanner.SevLow,
			title:       "BPF JIT hardening is disabled",
			detail:      "net.core.bpf_jit_harden=0 leaves the BPF JIT compiler without hardening, making it easier to exploit JIT-spray vulnerabilities.",
			remediation: "Set 'net.core.bpf_jit_harden=2' in /etc/sysctl.d/99-hardening.conf and apply with 'sysctl -p'.",
		},
	}

	for _, k := range knobs {
		data, err := os.ReadFile(k.path)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(data))
		if val != k.badValue {
			continue
		}
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("ebpf", k.path, k.title),
			Scanner:     "ebpf",
			Severity:    k.severity,
			Title:       k.title,
			Detail:      k.detail,
			Evidence:    fmt.Sprintf("%s = %s", k.path, val),
			Location:    k.path,
			Remediation: k.remediation,
		})
	}

	return findings
}
