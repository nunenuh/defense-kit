package main

import (
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/auth"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/code"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/environment"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/filesystem"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/network"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/persistence"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/process"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner/system"
)

// defaultRegistry returns a Registry pre-populated with all 37 built-in scanners.
func defaultRegistry() *scanner.Registry {
	r := scanner.NewRegistry()

	// Environment
	r.Register(environment.NewShellRCScanner())
	r.Register(environment.NewEnvVarsScanner())
	r.Register(environment.NewLDPreloadScanner())
	r.Register(environment.NewPAMScanner())

	// Persistence
	r.Register(persistence.NewCronScanner())
	r.Register(persistence.NewSystemdScanner())
	r.Register(persistence.NewScheduledScanner())

	// Process
	r.Register(process.NewSuspiciousScanner())
	r.Register(process.NewMemoryScanner())
	r.Register(process.NewClipboardScanner())

	// Filesystem
	r.Register(filesystem.NewIntegrityScanner())
	r.Register(filesystem.NewAnomaliesScanner())
	r.Register(filesystem.NewTimestompScanner())
	r.Register(filesystem.NewCapabilitiesScanner())
	r.Register(filesystem.NewSwapScanner())
	r.Register(filesystem.NewEncryptionScanner())

	// Network
	r.Register(network.NewPortsScanner())
	r.Register(network.NewConnectionsScanner())
	r.Register(network.NewDNSScanner())
	r.Register(network.NewFirewallScanner())
	r.Register(network.NewVPNScanner())

	// Auth
	r.Register(auth.NewSSHScanner())
	r.Register(auth.NewUsersScanner())
	r.Register(auth.NewBrowserScanner())

	// System
	r.Register(system.NewRootkitScanner())
	r.Register(system.NewBootScanner())
	r.Register(system.NewLogsScanner())
	r.Register(system.NewPackageMgrScanner())
	r.Register(system.NewSysctlScanner())
	r.Register(system.NewServicesScanner())
	r.Register(system.NewMACScanner())
	r.Register(system.NewUpdatesScanner())
	r.Register(system.NewAuditdScanner())

	// Code
	r.Register(code.NewCredentialsScanner())
	r.Register(code.NewSupplyChainScanner())
	r.Register(code.NewContainersScanner())
	r.Register(code.NewGitHooksScanner())
	r.Register(code.NewDockerRuntimeScanner())

	return r
}
