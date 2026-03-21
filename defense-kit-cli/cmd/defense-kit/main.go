package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile     string
	verbose     bool
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
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().BoolVar(&quick, "quick", false, "run a quick scan (skip expensive checks)")
	cmd.Flags().BoolVar(&diff, "diff", false, "show only changes since last baseline")
	cmd.Flags().StringVar(&category, "category", "", "limit scan to a specific category (e.g. network, files, users)")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text, json, yaml")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of concurrent scan workers")

	return cmd
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
			return errors.New("not yet implemented")
		},
	}
}

func newBaselineDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Show differences between current state and stored baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
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
			return errors.New("not yet implemented")
		},
	}
}
