package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/baseline"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/comply"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/config"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/hardener"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/monitor"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/schedule"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/tools"
)

var (
	cfgFile string
	verbose bool
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "defense-kit",
		Short: "Defensive security toolkit for Linux",
		Long: `defense-kit is a defensive security toolkit for Linux.
It provides scanning, baselining, and tooling capabilities to
audit, harden, and monitor your Linux systems.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.defense-kit.yaml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	root.AddCommand(newScanCmd())
	root.AddCommand(newHardenCmd())
	root.AddCommand(newBaselineCmd())
	root.AddCommand(newToolsCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newMonitorCmd())
	root.AddCommand(newScheduleCmd())
	root.AddCommand(newComplyCmd())

	return root
}

// outputsDir returns the directory used to store scan output and baselines.
func outputsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".defense-kit"
	}
	return fmt.Sprintf("%s/.defense-kit/outputs", home)
}

// baselinePath returns the path to the stored baseline file.
func baselinePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".defense-kit/baseline.json"
	}
	return fmt.Sprintf("%s/.defense-kit/baseline.json", home)
}

// hostname returns the current hostname, falling back to "unknown".
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// signalContext returns a context that is cancelled when SIGINT or SIGTERM is received.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

// executableDir returns the directory containing the running binary.
// Falls back to the current working directory on error.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// parseSeverity converts a severity string to a scanner.Severity value.
// Unrecognised strings default to SevLow.
func parseSeverity(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SevCritical
	case "high":
		return scanner.SevHigh
	case "medium":
		return scanner.SevMedium
	default:
		return scanner.SevLow
	}
}

func newScanCmd() *cobra.Command {
	var (
		quick        bool
		diff         bool
		category     string
		output       string
		concurrency  int
		htmlPath     string
		alertEnabled bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit the system (read-only)",
		Long: `Scan performs a read-only audit of the system.
It checks for security misconfigurations, vulnerability indicators,
and deviations from a known baseline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cfgFile, quick, diff, category, output, concurrency, htmlPath, alertEnabled)
		},
	}

	cmd.Flags().BoolVar(&quick, "quick", false, "run a quick scan (skip expensive checks)")
	cmd.Flags().BoolVar(&diff, "diff", false, "show only changes since last baseline")
	cmd.Flags().StringVar(&category, "category", "", "limit scan to a specific category (e.g. network, files, users)")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text, json, yaml")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of concurrent scan workers")
	cmd.Flags().StringVar(&htmlPath, "html", "", "path to write HTML report (e.g. report.html)")
	cmd.Flags().BoolVar(&alertEnabled, "alert", false, "send alerts via configured channels after scan")

	return cmd
}

func runScan(cfgPath string, quick, diff bool, category, output string, concurrency int, htmlPath string, alertEnabled bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Parse timeout from config.
	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	// CLI concurrency flag overrides config when explicitly set.
	if concurrency <= 0 {
		concurrency = cfg.Scan.Concurrency
	}

	// Build categories filter.
	var categories []string
	if category != "" {
		categories = []string{category}
	} else if len(cfg.Scan.Categories) > 0 {
		categories = cfg.Scan.Categories
	}

	toolRunner := tools.NewRunner()

	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Categories:   categories,
		Timeout:      timeout,
		Concurrency:  concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Quick:        quick,
		Diff:         diff,
		Verbose:      verbose,
		ToolRunner:   toolRunner,
	}

	ctx, cancel := signalContext()
	defer cancel()

	reg := defaultRegistry()
	engine := scanner.NewEngine(reg)

	fmt.Fprintf(os.Stdout, "Running scan (concurrency=%d, timeout=%s)...\n", concurrency, timeout)
	results := engine.Run(ctx, opts)

	// Render to terminal.
	term := reporter.NewTerminalReporter(os.Stdout)
	term.Render(results)

	// Save JSON report.
	outDir := outputsDir()
	jsonRep := reporter.NewJSONReporter(outDir)
	host := hostname()
	scanID, err := jsonRep.Write(results, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save JSON report: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "Report saved: %s\n", jsonRep.OutputPath(scanID))
	}

	// Generate HTML report if requested.
	if htmlPath != "" {
		// Probe template paths: working directory first, then relative to binary.
		templatePath := "templates/report.html"
		if _, statErr := os.Stat(templatePath); os.IsNotExist(statErr) {
			templatePath = filepath.Join(executableDir(), "..", "templates", "report.html")
		}
		hr := reporter.NewHTMLReporter(templatePath)
		if genErr := hr.Generate(results, host, htmlPath); genErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: HTML report failed: %v\n", genErr)
		} else {
			fmt.Fprintf(os.Stderr, "HTML report: %s\n", htmlPath)
		}
	}

	// Send alerts if requested.
	if alertEnabled {
		cfg2, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load config for alerts: %v\n", cfgErr)
		} else {
			dispatcher := reporter.NewAlertDispatcher()

			if cfg2.Alerts.Slack.WebhookURL != "" {
				minSev := parseSeverity(cfg2.Alerts.Slack.MinSeverity)
				dispatcher.Add(reporter.NewSlackAlerter(cfg2.Alerts.Slack.WebhookURL), minSev)
			}
			if cfg2.Alerts.Webhook.URL != "" {
				minSev := parseSeverity(cfg2.Alerts.Webhook.MinSeverity)
				dispatcher.Add(reporter.NewWebhookAlerter(cfg2.Alerts.Webhook.URL, cfg2.Alerts.Webhook.HMACSecret, cfg2.Alerts.Webhook.RequireTLS), minSev)
			}
			if cfg2.Alerts.Email.To != "" {
				minSev := parseSeverity(cfg2.Alerts.Email.MinSeverity)
				dispatcher.Add(reporter.NewEmailAlerter(cfg2.Alerts.Email.To, "defense-kit@localhost", cfg2.Alerts.Email.SMTPHost, "25"), minSev)
			}

			if dispErr := dispatcher.Dispatch(ctx, results, host, scanID); dispErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: alert dispatch: %v\n", dispErr)
			}
		}
	}

	// Load existing baseline.
	blPath := baselinePath()
	bl, loadErr := baseline.Load(blPath)
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load baseline: %v\n", loadErr)
	}

	// Collect all findings from results.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	// Auto-create baseline on first scan (empty baseline).
	if bl.ScanID == "" && loadErr == nil {
		newBaseline := baseline.Baseline{
			CreatedAt: time.Now(),
			Host:      host,
			ScanID:    scanID,
			Findings:  allFindings,
		}
		if err := baseline.Save(blPath, newBaseline); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save initial baseline: %v\n", err)
		} else {
			fmt.Fprintf(os.Stdout, "Initial baseline created at: %s\n", blPath)
		}
	} else if diff && loadErr == nil {
		// Show diff against baseline.
		diffResult := baseline.Diff(bl, allFindings)
		fmt.Fprintf(os.Stdout, "\nDIFF vs baseline (scan %s):\n", bl.ScanID)
		fmt.Fprintf(os.Stdout, "  New findings:      %d\n", len(diffResult.New))
		fmt.Fprintf(os.Stdout, "  Resolved findings: %d\n", len(diffResult.Resolved))
		fmt.Fprintf(os.Stdout, "  Changed findings:  %d\n", len(diffResult.Changed))
		fmt.Fprintf(os.Stdout, "  Unchanged:         %d\n", len(diffResult.Unchanged))

		if len(diffResult.New) > 0 {
			fmt.Fprintf(os.Stdout, "\nNEW findings:\n")
			for _, f := range diffResult.New {
				fmt.Fprintf(os.Stdout, "  [%s] %s\n", f.Severity.String(), f.Title)
			}
		}
		if len(diffResult.Resolved) > 0 {
			fmt.Fprintf(os.Stdout, "\nRESOLVED findings:\n")
			for _, f := range diffResult.Resolved {
				fmt.Fprintf(os.Stdout, "  [%s] %s\n", f.Severity.String(), f.Title)
			}
		}
	}

	return nil
}

func newHardenCmd() *cobra.Command {
	var (
		dryRun bool
		mode   string
	)

	cmd := &cobra.Command{
		Use:   "harden",
		Short: "Fix security issues found by scan (requires approval)",
		Long: `Harden runs a full scan, then offers to remediate fixable findings.

By default the command runs in dry-run mode: it shows what would be fixed
without making any changes. Use --mode to select a different approval mode.

Approval modes:
  dry-run     (default) Preview fixes only — no changes applied
  interactive Prompt for approval before each individual fix
  batch       Prompt once to approve all fixes together
  auto-low    Auto-approve LOW severity fixes; skip HIGH and CRITICAL`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHarden(cfgFile, dryRun, mode)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show fixes without applying (overrides --mode)")
	cmd.Flags().StringVar(&mode, "mode", "dry-run", "approval mode: interactive, batch, auto-low, dry-run")

	return cmd
}

// parseApprovalMode converts a mode string to a hardener.ApprovalMode.
func parseApprovalMode(s string) hardener.ApprovalMode {
	switch strings.ToLower(strings.ReplaceAll(s, "_", "-")) {
	case "interactive":
		return hardener.ModeInteractive
	case "batch":
		return hardener.ModeBatch
	case "auto-low", "autolow":
		return hardener.ModeAutoLow
	default:
		return hardener.ModeDryRun
	}
}

func runHarden(cfgPath string, dryRun bool, modeStr string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Parse timeout from config.
	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	// Build scanner options (same as runScan).
	toolRunner := tools.NewRunner()
	scanOpts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Timeout:      timeout,
		Concurrency:  cfg.Scan.Concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Verbose:      verbose,
		ToolRunner:   toolRunner,
	}

	ctx, cancel := signalContext()
	defer cancel()

	// Run scan to collect findings.
	fmt.Fprintln(os.Stdout, "Running scan to identify fixable findings...")
	reg := defaultRegistry()
	scanEngine := scanner.NewEngine(reg)
	results := scanEngine.Run(ctx, scanOpts)

	// Collect all findings.
	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}
	fmt.Fprintf(os.Stdout, "Scan complete: %d finding(s) found.\n\n", len(allFindings))

	// Build hardener registry.
	hardenReg := hardener.NewHardenerRegistry()
	hardenReg.Register(hardener.NewSSHHardener())
	hardenReg.Register(hardener.NewOSHardener())
	hardenReg.Register(hardener.NewFirewallHardener())
	hardenReg.Register(hardener.NewGitHardener())

	fixable := hardenReg.FixableFindings(allFindings)
	fmt.Fprintf(os.Stdout, "Fixable findings: %d of %d\n\n", len(fixable), len(allFindings))

	if len(fixable) == 0 {
		fmt.Fprintln(os.Stdout, "Nothing to harden.")
		return nil
	}

	// Resolve approval mode; --dry-run flag takes precedence.
	approvalMode := parseApprovalMode(modeStr)
	if dryRun {
		approvalMode = hardener.ModeDryRun
	}

	outDir := outputsDir()
	hardenEngine := hardener.NewEngine(hardenReg, outDir)

	opts := hardener.HardenOptions{
		Mode:      approvalMode,
		OutputDir: outDir,
		Findings:  allFindings,
		DryRun:    dryRun || approvalMode == hardener.ModeDryRun,
	}

	fmt.Fprintf(os.Stdout, "Hardening mode: %s\n\n", approvalMode.String())

	hardenResults, runErr := hardenEngine.Run(ctx, allFindings, opts)

	// Print results summary.
	applied := 0
	skipped := 0
	errored := 0
	for _, hr := range hardenResults {
		switch {
		case hr.Error != "":
			errored++
		case hr.Applied:
			applied++
		default:
			skipped++
		}
	}

	fmt.Fprintln(os.Stdout, "--- Harden Results ---")
	fmt.Fprintf(os.Stdout, "  Fixable:  %d\n", len(fixable))
	fmt.Fprintf(os.Stdout, "  Applied:  %d\n", applied)
	fmt.Fprintf(os.Stdout, "  Skipped:  %d\n", skipped)
	fmt.Fprintf(os.Stdout, "  Errors:   %d\n", errored)
	fmt.Fprintln(os.Stdout)

	if opts.DryRun || approvalMode == hardener.ModeDryRun {
		fmt.Fprintln(os.Stdout, "(Dry-run: no changes were applied)")
		fmt.Fprintln(os.Stdout)
		for _, hr := range hardenResults {
			fmt.Fprintf(os.Stdout, "  [WOULD FIX] [%s] %s\n    Fix: %s\n",
				hr.Finding.Severity.String(), hr.Finding.Title, hr.Plan.Description)
		}
	} else {
		for _, hr := range hardenResults {
			switch {
			case hr.Error != "":
				fmt.Fprintf(os.Stdout, "  [ERROR]   [%s] %s — %s\n",
					hr.Finding.Severity.String(), hr.Finding.Title, hr.Error)
			case hr.Applied:
				fmt.Fprintf(os.Stdout, "  [FIXED]   [%s] %s\n",
					hr.Finding.Severity.String(), hr.Finding.Title)
			default:
				fmt.Fprintf(os.Stdout, "  [SKIPPED] [%s] %s\n",
					hr.Finding.Severity.String(), hr.Finding.Title)
			}
		}
	}

	// Print rollback script path if any fixes were applied.
	if applied > 0 {
		fmt.Fprintf(os.Stdout, "\nRollback scripts written to: %s\n",
			filepath.Join(outDir, "rollback-*.sh"))
	}

	return runErr
}

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage system baselines",
		Long:  `baseline manages snapshots of the system state used as a reference for diff and drift detection.`,
	}

	cmd.AddCommand(newBaselineUpdateCmd())
	cmd.AddCommand(newBaselineDiffCmd())

	return cmd
}

func newBaselineUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update the stored baseline to the current system state",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaselineUpdate()
		},
	}
}

func runBaselineUpdate() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Timeout:      timeout,
		Concurrency:  cfg.Scan.Concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Verbose:      verbose,
	}

	ctx, cancel := signalContext()
	defer cancel()

	reg := defaultRegistry()
	engine := scanner.NewEngine(reg)

	fmt.Fprintln(os.Stdout, "Running scan to update baseline...")
	results := engine.Run(ctx, opts)

	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	host := hostname()

	// Save JSON report.
	outDir := outputsDir()
	jsonRep := reporter.NewJSONReporter(outDir)
	scanID, err := jsonRep.Write(results, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save JSON report: %v\n", err)
		scanID = fmt.Sprintf("manual-%d", time.Now().Unix())
	}

	blPath := baselinePath()
	newBaseline := baseline.Baseline{
		CreatedAt: time.Now(),
		Host:      host,
		ScanID:    scanID,
		Findings:  allFindings,
	}
	if err := baseline.Save(blPath, newBaseline); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Baseline updated: %d findings saved to %s\n", len(allFindings), blPath)
	return nil
}

func newBaselineDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Show differences between current state and stored baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaselineDiff()
		},
	}
}

func runBaselineDiff() error {
	blPath := baselinePath()
	bl, err := baseline.Load(blPath)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	if bl.ScanID == "" {
		return fmt.Errorf("no baseline found at %s — run 'defense-kit scan' or 'defense-kit baseline update' first", blPath)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Timeout:      timeout,
		Concurrency:  cfg.Scan.Concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Verbose:      verbose,
	}

	ctx, cancel := signalContext()
	defer cancel()

	reg := defaultRegistry()
	engine := scanner.NewEngine(reg)

	fmt.Fprintln(os.Stdout, "Running scan for diff...")
	results := engine.Run(ctx, opts)

	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	diffResult := baseline.Diff(bl, allFindings)

	fmt.Fprintf(os.Stdout, "\nDIFF vs baseline (scan %s, created %s):\n",
		bl.ScanID, bl.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "  New findings:      %d\n", len(diffResult.New))
	fmt.Fprintf(os.Stdout, "  Resolved findings: %d\n", len(diffResult.Resolved))
	fmt.Fprintf(os.Stdout, "  Changed findings:  %d\n", len(diffResult.Changed))
	fmt.Fprintf(os.Stdout, "  Unchanged:         %d\n", len(diffResult.Unchanged))

	if len(diffResult.New) > 0 {
		fmt.Fprintf(os.Stdout, "\nNEW findings:\n")
		for _, f := range diffResult.New {
			fmt.Fprintf(os.Stdout, "  [%s] %s — %s\n", f.Severity.String(), f.Title, f.Location)
		}
	}
	if len(diffResult.Resolved) > 0 {
		fmt.Fprintf(os.Stdout, "\nRESOLVED findings:\n")
		for _, f := range diffResult.Resolved {
			fmt.Fprintf(os.Stdout, "  [%s] %s — %s\n", f.Severity.String(), f.Title, f.Location)
		}
	}
	if len(diffResult.Changed) > 0 {
		fmt.Fprintf(os.Stdout, "\nCHANGED findings (severity shifted):\n")
		for _, fc := range diffResult.Changed {
			fmt.Fprintf(os.Stdout, "  [%s->%s] %s\n",
				fc.OldSeverity.String(), fc.Finding.Severity.String(), fc.Finding.Title)
		}
	}

	return nil
}

func newToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage and verify required external tools",
		Long:  `tools manages the external binaries and utilities that defense-kit depends on.`,
	}

	cmd.AddCommand(newToolsCheckCmd())

	return cmd
}

func newToolsCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check that all required tools are installed and available",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runToolsCheck()
		},
	}
}

func runToolsCheck() error {
	reg := defaultRegistry()
	all := reg.All()

	fmt.Fprintf(os.Stdout, "Registered scanners (%d total):\n\n", len(all))
	fmt.Fprintf(os.Stdout, "%-30s %-15s %-10s %s\n", "NAME", "CATEGORY", "AVAILABLE", "REQUIRED TOOLS")
	fmt.Fprintf(os.Stdout, "%-30s %-15s %-10s %s\n",
		"------------------------------",
		"---------------",
		"----------",
		"--------------",
	)

	for _, s := range all {
		avail := "yes"
		if !s.Available() {
			avail = "no"
		}
		tools := s.RequiredTools()
		toolStr := ""
		if len(tools) > 0 {
			for i, t := range tools {
				if i > 0 {
					toolStr += ", "
				}
				toolStr += t
			}
		} else {
			toolStr = "(none)"
		}
		fmt.Fprintf(os.Stdout, "%-30s %-15s %-10s %s\n", s.Name(), s.Category(), avail, toolStr)
	}

	available := reg.Available()
	fmt.Fprintf(os.Stdout, "\n%d of %d scanners available in current environment.\n",
		len(available), len(all))

	// External tools
	toolReg := tools.DefaultToolRegistry()
	statuses := toolReg.CheckAll()

	fmt.Fprintf(os.Stdout, "\nExternal tools (%d registered):\n\n", len(statuses))
	fmt.Fprintf(os.Stdout, "%-20s %-15s %-10s %-12s %s\n", "NAME", "CATEGORY", "INSTALLED", "VERSION", "PATH")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("-", 80))

	installed := 0
	for _, s := range statuses {
		instStr := "no"
		if s.Installed {
			instStr = "yes"
			installed++
		}
		ver := s.Version
		if ver == "" {
			ver = "-"
		}
		path := s.Path
		if path == "" {
			path = "-"
		}
		fmt.Fprintf(os.Stdout, "%-20s %-15s %-10s %-12s %s\n", s.Def.Name, s.Def.Category, instStr, ver, path)
	}
	fmt.Fprintf(os.Stdout, "\n%d of %d external tools installed.\n", installed, len(statuses))

	return nil
}

// newReportCmd returns the "report" parent command.
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate reports from last scan",
		Long:  `report generates formatted output from a previously saved scan result.`,
	}

	cmd.AddCommand(newReportHTMLCmd())

	return cmd
}

// newReportHTMLCmd returns the "report html <output-path>" subcommand.
func newReportHTMLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "html [output-path]",
		Short: "Generate HTML report from last scan",
		Long: `Generate a self-contained HTML report from the most recent scan saved in
the outputs directory (~/.defense-kit/outputs).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReportHTML(args[0])
		},
	}
}

// runReportHTML loads the latest JSON scan report and generates an HTML file.
func runReportHTML(outputPath string) error {
	outDir := outputsDir()

	// Find the most-recently-modified findings.json under outDir.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return fmt.Errorf("report html: read outputs dir %q: %w", outDir, err)
	}

	// ReadDir returns entries sorted by name; scan IDs are time-stamped so
	// the last entry is the most recent.
	var latestJSON string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(outDir, e.Name(), "findings.json")
		if _, statErr := os.Stat(candidate); statErr == nil {
			latestJSON = candidate
			break
		}
	}

	if latestJSON == "" {
		return fmt.Errorf("report html: no scan reports found in %s — run 'defense-kit scan' first", outDir)
	}

	// Parse the JSON report.
	data, err := os.ReadFile(latestJSON)
	if err != nil {
		return fmt.Errorf("report html: read %q: %w", latestJSON, err)
	}

	var scanReport reporter.ScanReport
	if err := json.Unmarshal(data, &scanReport); err != nil {
		return fmt.Errorf("report html: parse %q: %w", latestJSON, err)
	}

	// Resolve template path.
	templatePath := "templates/report.html"
	if _, statErr := os.Stat(templatePath); os.IsNotExist(statErr) {
		templatePath = filepath.Join(executableDir(), "..", "templates", "report.html")
	}

	hr := reporter.NewHTMLReporter(templatePath)
	if err := hr.Generate(scanReport.Results, scanReport.Host, outputPath); err != nil {
		return fmt.Errorf("report html: generate: %w", err)
	}

	fmt.Fprintf(os.Stdout, "HTML report written to: %s\n", outputPath)
	return nil
}

// ---------------------------------------------------------------------------
// Monitor command
// ---------------------------------------------------------------------------

func newMonitorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "monitor",
		Short: "Quick scan + diff against baseline (for /loop)",
		Long:  `monitor performs a quick security scan and shows the diff against the stored baseline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMonitor()
		},
	}
}

func runMonitor() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	reg := defaultRegistry()
	blPath := baselinePath()
	outDir := outputsDir()

	mon := monitor.New(reg, blPath, outDir)

	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	toolRunner := tools.NewRunner()

	// Use QuickCategories from config when available.
	categories := cfg.Monitor.QuickCategories
	if len(categories) == 0 {
		categories = cfg.Scan.Categories
	}

	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Categories:   categories,
		Timeout:      timeout,
		Concurrency:  cfg.Scan.Concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Quick:        true,
		Verbose:      verbose,
		ToolRunner:   toolRunner,
	}

	ctx, cancel := signalContext()
	defer cancel()

	result, err := mon.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("monitor run: %w", err)
	}

	if result.IsFirstRun {
		fmt.Fprintf(os.Stdout, "Baseline created at %s\n", result.BaselinePath)
		return nil
	}

	diff := result.Diff
	fmt.Fprintf(os.Stdout, "Monitor: %d new, %d resolved, %d changed findings\n",
		len(diff.New), len(diff.Resolved), len(diff.Changed))

	if len(diff.New) > 0 {
		fmt.Fprintf(os.Stdout, "\nNEW findings:\n")
		for _, f := range diff.New {
			fmt.Fprintf(os.Stdout, "  [%s] %s — %s\n", f.Severity.String(), f.Title, f.Location)
		}
	}

	if len(diff.Resolved) > 0 {
		fmt.Fprintf(os.Stdout, "\nRESOLVED findings (good news):\n")
		for _, f := range diff.Resolved {
			fmt.Fprintf(os.Stdout, "  [%s] %s — %s\n", f.Severity.String(), f.Title, f.Location)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Schedule command group
// ---------------------------------------------------------------------------

func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled scans",
		Long:  `schedule manages periodic automated security scans using systemd or cron.`,
	}

	cmd.AddCommand(newScheduleEnableCmd())
	cmd.AddCommand(newScheduleDisableCmd())
	cmd.AddCommand(newScheduleStatusCmd())

	return cmd
}

func newScheduleEnableCmd() *cobra.Command {
	var (
		interval string
		mode     string
	)

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable scheduled scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScheduleEnable(interval, mode)
		},
	}

	cmd.Flags().StringVar(&interval, "interval", "6h", "scan interval (e.g. 30m, 6h, 24h)")
	cmd.Flags().StringVar(&mode, "mode", "quick", "scan mode: quick or full")

	return cmd
}

func runScheduleEnable(intervalStr, mode string) error {
	dur, err := time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("invalid interval %q: %w", intervalStr, err)
	}

	backend := schedule.DetectBackend()

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine binary path: %w", err)
	}

	cfg := schedule.Config{
		Interval:   dur,
		ScanMode:   mode,
		Backend:    backend,
		BinaryPath: binaryPath,
	}

	if err := schedule.Enable(cfg); err != nil {
		return fmt.Errorf("enable schedule: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Scheduled %s scan every %s via %s\n", mode, intervalStr, backend)
	return nil
}

func newScheduleDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable scheduled scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScheduleDisable()
		},
	}
}

func runScheduleDisable() error {
	if err := schedule.Disable(); err != nil {
		return fmt.Errorf("disable schedule: %w", err)
	}
	fmt.Fprintln(os.Stdout, "Scheduled scanning disabled")
	return nil
}

func newScheduleStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show scheduled scan status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScheduleStatus()
		},
	}
}

func runScheduleStatus() error {
	st := schedule.GetStatus()
	if !st.Enabled {
		fmt.Fprintln(os.Stdout, "Scheduled scanning: disabled")
		return nil
	}
	fmt.Fprintf(os.Stdout, "Scheduled scanning: enabled\n")
	fmt.Fprintf(os.Stdout, "  Backend:  %s\n", st.Backend)
	fmt.Fprintf(os.Stdout, "  Interval: %s\n", st.Interval)
	return nil
}

// ---------------------------------------------------------------------------
// Comply command
// ---------------------------------------------------------------------------

func newComplyCmd() *cobra.Command {
	var framework string

	cmd := &cobra.Command{
		Use:   "comply",
		Short: "Map findings to compliance frameworks",
		Long: `comply runs a full scan and maps the findings to a compliance framework.

Supported frameworks:
  cis    CIS Benchmarks for Linux (default)
  soc2   SOC 2 controls (future)
  owasp  OWASP controls (future)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runComply(cfgFile, framework)
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "cis", "compliance framework: cis, soc2, owasp")

	return cmd
}

func runComply(cfgPath string, frameworkStr string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	timeout, err := time.ParseDuration(cfg.Scan.Timeout)
	if err != nil {
		timeout = 60 * time.Second
	}

	toolRunner := tools.NewRunner()
	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Timeout:      timeout,
		Concurrency:  cfg.Scan.Concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Verbose:      verbose,
		ToolRunner:   toolRunner,
	}

	ctx, cancel := signalContext()
	defer cancel()

	fmt.Fprintln(os.Stdout, "Running full scan for compliance mapping...")

	reg := defaultRegistry()
	engine := scanner.NewEngine(reg)
	results := engine.Run(ctx, opts)

	var allFindings []scanner.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	fmt.Fprintf(os.Stdout, "Scan complete: %d finding(s) found.\n\n", len(allFindings))

	fw := comply.Framework(strings.ToLower(frameworkStr))
	switch fw {
	case comply.FrameworkCIS, comply.FrameworkSOC2, comply.FrameworkOWASP:
		// valid
	default:
		return fmt.Errorf("unknown framework %q — supported: cis, soc2, owasp", frameworkStr)
	}

	compResult := comply.MapFindings(allFindings, fw)
	fmt.Fprint(os.Stdout, comply.FormatReport(compResult))

	return nil
}
