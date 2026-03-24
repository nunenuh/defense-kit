# Defense: Container Escape

## Threat

Attackers break out of Docker/container isolation to gain host access. Uses cgroups release_agent abuse, kernel exploits, mounted Docker socket, or privileged container capabilities.

**Key CVEs:** CVE-2022-0492 (cgroups), CVE-2024-21626 (runc Leaky Vessels)

## Escape Vectors

1. **cgroups release_agent** — write arbitrary path to execute on host
2. **Docker socket mount** — `/var/run/docker.sock` inside container = root on host
3. **Privileged container** — `--privileged` disables all security boundaries
4. **Host PID/network namespace** — visibility into host processes
5. **Kernel exploits** — escape via vulnerable kernel syscalls
6. **runc vulnerabilities** — container runtime bugs

## Detection

### defense-kit scanners
- `docker_runtime` — privileged containers, socket perms, host mounts
- `containers` — Dockerfile linting
- `capabilities` — dangerous caps (CAP_SYS_ADMIN)

### Manual verification
```bash
# Docker socket permissions
ls -la /var/run/docker.sock
stat -c '%a %U:%G' /var/run/docker.sock  # should be 660 root:docker

# Privileged containers
docker ps -q | xargs -I{} docker inspect --format '{{.Name}}: privileged={{.HostConfig.Privileged}}' {}

# Dangerous mounts
docker ps -q | xargs -I{} docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' {}

# Containers with host namespaces
docker ps -q | xargs -I{} docker inspect --format '{{.Name}}: PID={{.HostConfig.PidMode}} NET={{.HostConfig.NetworkMode}}' {}

# Check kernel version for known escape CVEs
uname -r
```

## Response

1. **Stop privileged containers**: `docker stop <container>`
2. **Fix socket permissions**: `chmod 660 /var/run/docker.sock`
3. **Remove host mounts**: rebuild without `-v /:/host`
4. **Update kernel and runc**: patch known escape CVEs
5. **Audit**: check what was accessed on host from container

## Prevention

```bash
# Never use --privileged in production
# Use rootless Docker
dockerd-rootless-setuptool.sh install

# Restrict Docker socket
chmod 660 /var/run/docker.sock
# Don't mount socket into containers

# Use Seccomp + AppArmor (default Docker profiles block most escapes)
docker run --security-opt seccomp=default --security-opt apparmor=docker-default

# Drop all capabilities, add only what's needed
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE

# Use read-only root filesystem
docker run --read-only --tmpfs /tmp
```

## References
- [Container Escape Techniques - Unit42](https://unit42.paloaltonetworks.com/container-escape-techniques/)
- [CVE-2022-0492 cgroups Escape - Sysdig](https://www.sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig)
- [Container Escape via Kernel Exploitation - CyberArk](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)
