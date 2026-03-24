# Defense: Credential Theft

## Threat

Secrets leaked in code, git history, environment variables, browser stores, or config files.

## Detection

### defense-kit scanners
- `credentials` — AWS keys, private keys, API tokens in files + git history
- `ssh` — weak SSH config, unauthorized authorized_keys
- `browser` — Chrome/Firefox saved passwords
- `env_vars` — LD_PRELOAD, PROMPT_COMMAND, proxy hijacking

### Manual verification
```bash
# Git history secrets
gitleaks detect --source . --verbose
git log --all -p | grep -i "AKIA\|BEGIN.*PRIVATE KEY\|password\s*="

# Environment
env | grep -i "key\|token\|secret\|password\|api"
cat /etc/environment

# SSH keys
for user in /home/*/; do echo "=== $user ===" && cat "${user}.ssh/authorized_keys" 2>/dev/null; done

# Browser stores
find /home -name "Login Data" -o -name "logins.json" 2>/dev/null
```

## Response

1. **Rotate immediately**: every exposed key, token, password
2. **Check access logs**: AWS CloudTrail, GitHub audit log, server auth.log
3. **Revoke tokens**: GitHub, AWS IAM, API keys
4. **Remove from git**: `git filter-branch` or BFG Repo-Cleaner
5. **Scan all repos**: `defense-kit scan --category code`

## Prevention

- Install gitleaks pre-commit hook: `gitleaks protect --staged`
- Use secret managers (AWS Secrets Manager, HashiCorp Vault)
- Never commit .env files: add to .gitignore
- Enable MFA on all services
- `defense-kit harden` fixes SSH config

## Quick Reference

```bash
defense-kit scan --category code           # credentials + git history
defense-kit scan --category auth           # SSH + users + browser
gitleaks detect --source . --verbose       # external deep scan
```
