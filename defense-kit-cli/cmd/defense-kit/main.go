package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/baseline"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/config"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/reporter"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
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
	root.AddCommand(newBaselineCmd())
	root.AddCommand(newToolsCmd())

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

func newScanCmd() *cobra.Command {
	var (
		quick       bool
		diff        bool
		category    string
		output      string
		concurrency int
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit the system (read-only)",
		Long: `Scan performs a read-only audit of the system.
It checks for security misconfigurations, vulnerability indicators,
and deviations from a known baseline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cfgFile, quick, diff, category, output, concurrency)
		},
	}

	cmd.Flags().BoolVar(&quick, "quick", false, "run a quick scan (skip expensive checks)")
	cmd.Flags().BoolVar(&diff, "diff", false, "show only changes since last baseline")
	cmd.Flags().StringVar(&category, "category", "", "limit scan to a specific category (e.g. network, files, users)")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text, json, yaml")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of concurrent scan workers")

	return cmd
}

func runScan(cfgPath string, quick, diff bool, category, output string, concurrency int) error {
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

	opts := scanner.ScanOptions{
		ExcludePaths: cfg.Scan.ExcludePaths,
		Categories:   categories,
		Timeout:      timeout,
		Concurrency:  concurrency,
		UseExtTools:  cfg.Tools.PreferExternal,
		Quick:        quick,
		Diff:         diff,
		Verbose:      verbose,
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

	return nil
}
