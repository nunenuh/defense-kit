# External Tool Reference

## Quick Install (Debian/Ubuntu)

```bash
sudo apt install rkhunter chkrootkit lynis clamav aide debsums nmap
pip3 install ssh-audit
```

## Tool Catalog

| Tool | Category | Scanner | What It Adds |
|------|----------|---------|-------------|
| rkhunter | system | rootkit | Signature-based rootkit detection |
| chkrootkit | system | rootkit | Alternative rootkit scanner |
| lynis | system | (planned) | Full CIS benchmark audit |
| ClamAV | malware | (planned) | Virus/malware signature database |
| gitleaks | secrets | credentials | 700+ secret patterns, git history |
| trufflehog | secrets | credentials | Credential verification |
| trivy | deps | supply_chain | CVE database, SBOM |
| grype | deps | supply_chain | Alternative CVE scanner |
| hadolint | containers | containers | Dockerfile best practices |
| dockle | containers | containers | Container image audit |
| ssh-audit | ssh | ssh | Algorithm and config analysis |
| semgrep | code | (planned) | Multi-language SAST |
| bandit | code | (planned) | Python security linting |
| nmap | network | ports | Service fingerprinting |
| aide | filesystem | (planned) | File integrity monitoring |
| debsums | forensics | package_manager | Package checksum verification |
| ss | network | ports | Socket statistics (built-in) |

## Check Availability

```bash
defense-kit tools check
```
