# Defense: Supply Chain Attacks

## Threat

Compromised packages, malicious dependencies, typosquatting, trojaned binaries.

## Detection

### defense-kit scanners
- `supply_chain` — CVEs in dependencies via trivy/grype
- `package_manager` — modified package files via debsums
- `containers` — Dockerfile issues via hadolint
- `git_hooks` — malicious pre-commit/post-checkout hooks

### Manual verification
```bash
# Package integrity
debsums -c                                # modified files
dpkg --verify                             # alternative
apt list --upgradable 2>/dev/null          # pending updates

# Dependencies
trivy fs --scanners vuln .                # CVE scan
npm audit 2>/dev/null                     # Node.js
pip-audit 2>/dev/null                     # Python

# Git hooks
find . -path '*/.git/hooks/*' -executable -type f
```

## Response

1. **Pin versions**: use lockfiles (package-lock.json, Pipfile.lock, go.sum)
2. **Verify**: compare binary hashes against official releases
3. **Update**: patch vulnerable dependencies immediately
4. **Audit**: review recently added dependencies

## Prevention

- Use lockfiles and verify checksums
- Enable auto-updates for security patches
- Scan in CI: `defense-kit scan --profile ci`
- Use `defense-kit schedule enable` for continuous monitoring

## Quick Reference

```bash
defense-kit scan --category code           # supply chain + containers + git hooks
debsums -c                                 # check package integrity
trivy fs --format json .                   # dependency CVEs
```
