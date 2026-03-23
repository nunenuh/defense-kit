package code

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const dockerSocketPath = "/var/run/docker.sock"

// DockerRuntimeScanner checks the Docker socket permissions and inspects
// running containers for privilege escalation risks.
type DockerRuntimeScanner struct {
	socketPath string
}

// NewDockerRuntimeScanner creates a DockerRuntimeScanner with production
// defaults.
func NewDockerRuntimeScanner() *DockerRuntimeScanner {
	return &DockerRuntimeScanner{socketPath: dockerSocketPath}
}

// NewDockerRuntimeScannerWithSocket creates a DockerRuntimeScanner with a
// custom socket path (used in tests).
func NewDockerRuntimeScannerWithSocket(socketPath string) *DockerRuntimeScanner {
	return &DockerRuntimeScanner{socketPath: socketPath}
}

func (s *DockerRuntimeScanner) Name() string            { return "docker_runtime" }
func (s *DockerRuntimeScanner) Category() string        { return "code" }
func (s *DockerRuntimeScanner) RequiresRoot() bool      { return false }
func (s *DockerRuntimeScanner) RequiredTools() []string { return nil }
func (s *DockerRuntimeScanner) OptionalTools() []string { return []string{"docker"} }
func (s *DockerRuntimeScanner) Available() bool         { return true }
func (s *DockerRuntimeScanner) Description() string {
	return "Checks Docker socket permissions and inspects running containers for privileged mode, host networking, root users, and dangerous host mounts."
}

// Scan audits the Docker socket and running container configurations.
func (s *DockerRuntimeScanner) Scan(ctx context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	findings = append(findings, s.checkSocketPermissions()...)
	findings = append(findings, s.checkRunningContainers(ctx, opts)...)

	if len(findings) == 0 {
		return nil, nil
	}
	return findings, nil
}

// checkSocketPermissions checks whether the Docker socket is world-readable
// or world-writable, which would allow any user to control Docker.
func (s *DockerRuntimeScanner) checkSocketPermissions() []scanner.Finding {
	info, err := os.Stat(s.socketPath)
	if err != nil {
		// Docker not installed or socket not present — skip.
		return nil
	}

	mode := info.Mode()

	// World-readable or world-writable Docker socket is CRITICAL.
	if mode&0o006 != 0 {
		perm := "world-readable"
		if mode&0o002 != 0 {
			perm = "world-writable"
		}
		return []scanner.Finding{
			{
				ID:       scanner.GenerateFindingID(s.Name(), s.socketPath, "docker socket world accessible"),
				Scanner:  s.Name(),
				Severity: scanner.SevCritical,
				Title:    fmt.Sprintf("Docker socket is %s — equivalent to root access", perm),
				Detail: fmt.Sprintf(
					"The Docker socket at %s has permissions %s. Any user who can read or write the Docker socket can run containers with root privileges on the host, effectively granting full root access.",
					s.socketPath, mode.String(),
				),
				Evidence:    fmt.Sprintf("socket: %s, permissions: %s", s.socketPath, mode.String()),
				Location:    s.socketPath,
				Remediation: fmt.Sprintf("Restrict Docker socket access: run 'chmod 660 %s && chown root:docker %s'. Only add users to the docker group if they are trusted administrators.", s.socketPath, s.socketPath),
				References: []string{
					"https://docs.docker.com/engine/security/",
					"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker+socket",
				},
			},
		}
	}

	return nil
}

// checkRunningContainers runs `docker ps --format json` and inspects each
// container for security issues.
func (s *DockerRuntimeScanner) checkRunningContainers(ctx context.Context, opts scanner.ScanOptions) []scanner.Finding {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("docker") {
		return nil
	}

	out, err := opts.ToolRunner.Run(ctx, "docker", []string{"ps", "--format", "{{json .}}"})
	if err != nil && len(out) == 0 {
		return nil
	}

	var findings []scanner.Finding

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse each JSON line.
		var raw map[string]interface{}
		if jsonErr := json.Unmarshal([]byte(line), &raw); jsonErr != nil {
			continue
		}

		containerID := stringField(raw, "ID")
		containerName := stringField(raw, "Names")
		if containerID == "" {
			containerID = containerName
		}
		label := containerName
		if label == "" {
			label = containerID
		}

		mounts := stringField(raw, "Mounts")
		networkMode := stringField(raw, "NetworkMode")
		image := stringField(raw, "Image")

		// Flag host network mode → HIGH.
		if strings.EqualFold(networkMode, "host") {
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID(s.Name(), containerID, "container host network"),
				Scanner:  s.Name(),
				Severity: scanner.SevHigh,
				Title:    fmt.Sprintf("Container %q is using host networking", label),
				Detail:   "Containers with --network=host share the host network namespace. This bypasses network isolation and allows the container to listen on host ports and access host network interfaces.",
				Evidence: fmt.Sprintf("container: %s, image: %s, network_mode: %s", label, image, networkMode),
				Location: containerID,
				Remediation: "Remove the --network=host flag from the container run command or Docker Compose configuration. Use proper port mapping instead.",
				References: []string{
					"https://docs.docker.com/network/host/",
				},
			})
		}

		// Flag dangerous host mounts (/ mounted at any path) → CRITICAL.
		if containsHostRootMount(mounts) {
			findings = append(findings, scanner.Finding{
				ID:       scanner.GenerateFindingID(s.Name(), containerID, "container host root mount"),
				Scanner:  s.Name(),
				Severity: scanner.SevCritical,
				Title:    fmt.Sprintf("Container %q has the host root filesystem mounted", label),
				Detail:   "The container has the host root filesystem (/) mounted as a volume. This gives the container unrestricted access to the host filesystem, equivalent to running as root on the host.",
				Evidence: fmt.Sprintf("container: %s, image: %s, mounts: %s", label, image, mounts),
				Location: containerID,
				Remediation: "Remove the -v /:/host (or equivalent) volume mount from the container configuration. Mount only specific directories that are needed.",
				References: []string{
					"https://docs.docker.com/engine/security/",
				},
			})
		}
	}

	// Also try docker inspect for privileged and user info.
	findings = append(findings, s.inspectContainers(ctx, opts)...)

	return findings
}

// inspectContainers runs `docker inspect` on all running containers to detect
// privileged mode and root user.
func (s *DockerRuntimeScanner) inspectContainers(ctx context.Context, opts scanner.ScanOptions) []scanner.Finding {
	if opts.ToolRunner == nil || !opts.ToolRunner.Available("docker") {
		return nil
	}

	// Get list of running container IDs.
	idOut, err := opts.ToolRunner.Run(ctx, "docker", []string{"ps", "-q"})
	if err != nil && len(idOut) == 0 {
		return nil
	}

	ids := strings.Fields(string(idOut))
	if len(ids) == 0 {
		return nil
	}

	inspectArgs := append([]string{"inspect"}, ids...)
	inspectOut, err := opts.ToolRunner.Run(ctx, "docker", inspectArgs)
	if err != nil && len(inspectOut) == 0 {
		return nil
	}

	var containers []map[string]interface{}
	if jsonErr := json.Unmarshal(inspectOut, &containers); jsonErr != nil {
		return nil
	}

	var findings []scanner.Finding

	for _, c := range containers {
		id := stringField(c, "Id")
		name := ""
		if names, ok := c["Name"].(string); ok {
			name = strings.TrimPrefix(names, "/")
		}
		label := name
		if label == "" {
			if id != "" && len(id) > 12 {
				label = id[:12]
			} else {
				label = id
			}
		}

		// Check HostConfig.Privileged.
		if hostCfg, ok := c["HostConfig"].(map[string]interface{}); ok {
			if priv, ok := hostCfg["Privileged"].(bool); ok && priv {
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID(s.Name(), id, "container privileged"),
					Scanner:  s.Name(),
					Severity: scanner.SevCritical,
					Title:    fmt.Sprintf("Container %q is running in privileged mode", label),
					Detail:   "Privileged containers have nearly the same access to the host as a root process. They can access all host devices, load kernel modules, and manipulate the host network stack.",
					Evidence: fmt.Sprintf("container: %s, privileged: true", label),
					Location: id,
					Remediation: "Remove the --privileged flag. Grant only specific capabilities needed by the container using --cap-add.",
					References: []string{
						"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
					},
				})
			}
		}

		// Check Config.User — empty or "root" means the container runs as root.
		if cfg, ok := c["Config"].(map[string]interface{}); ok {
			user := ""
			if u, ok := cfg["User"].(string); ok {
				user = strings.TrimSpace(u)
			}
			if user == "" || user == "root" || user == "0" {
				findings = append(findings, scanner.Finding{
					ID:       scanner.GenerateFindingID(s.Name(), id, "container running as root"),
					Scanner:  s.Name(),
					Severity: scanner.SevMedium,
					Title:    fmt.Sprintf("Container %q is running as root", label),
					Detail:   "The container is running as the root user (uid 0). If the container is compromised, the attacker may be able to escape to the host if other protections are not in place.",
					Evidence: fmt.Sprintf("container: %s, user: %q", label, user),
					Location: id,
					Remediation: "Add a USER instruction to the Dockerfile to run the container as a non-root user. Use --user flag at runtime or set runAsNonRoot in Kubernetes pod security context.",
					References: []string{
						"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
					},
				})
			}
		}
	}

	return findings
}

// containsHostRootMount returns true if the mounts string contains a host
// root mount pattern such as "/:/host" or "/:" .
func containsHostRootMount(mounts string) bool {
	// Look for patterns where the source is / (host root).
	// docker ps --format "{{json .}}" Mounts field is a comma-separated list.
	for _, m := range strings.Split(mounts, ",") {
		m = strings.TrimSpace(m)
		if strings.HasPrefix(m, "/:/") || m == "/:" {
			return true
		}
		// Also catch JSON-style source field "Source":"/"
		if strings.Contains(m, `"Source":"/"`) || strings.Contains(m, `"source":"/"`) {
			return true
		}
	}
	return false
}

// stringField safely extracts a string from a map[string]interface{}.
func stringField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
