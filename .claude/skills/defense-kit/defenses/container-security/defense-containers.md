# Defense: Container Security

## Threat

Docker socket exposure (instant root), privileged containers, host filesystem mounts, image vulnerabilities.

## Detection

### defense-kit scanners
- `containers` — Dockerfile linting via hadolint
- `docker_runtime` — socket perms, privileged containers, host mounts, root user

### Manual verification
```bash
# Docker socket
ls -la /var/run/docker.sock
stat -c '%a' /var/run/docker.sock         # should be 660, not 666

# Running containers
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
docker inspect --format '{{.HostConfig.Privileged}}' $(docker ps -q) 2>/dev/null

# Host mounts
docker inspect --format '{{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' $(docker ps -q) 2>/dev/null
```

## Response

1. **Stop**: `docker stop <container>` for privileged containers
2. **Fix permissions**: `chmod 660 /var/run/docker.sock`
3. **Rebuild**: fix Dockerfile (non-root USER, no --privileged)
4. **Scan images**: `trivy image <image:tag>`

## Prevention

- Never run `--privileged` in production
- Use rootless Docker: `dockerd-rootless`
- Don't mount `/var/run/docker.sock` into containers
- Pin image versions (no `:latest`)
- Add HEALTHCHECK to Dockerfiles

## Quick Reference

```bash
defense-kit scan --category code           # containers + docker_runtime
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
hadolint Dockerfile                        # lint Dockerfile
```
