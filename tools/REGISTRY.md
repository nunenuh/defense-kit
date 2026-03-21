# External Tool Registry

Defense-kit integrates 17 external security tools to augment its native Go scanners.
All tools are optional — scanners degrade gracefully to pure-Go checks when a tool is absent.
Use `defense-kit tools check` (or `preflight`) to see which tools are installed on the current host.

---

## Summary Table

| Name | Binary | Category | Install Method | Min Version | Used By Scanner(s) |
|------|--------|----------|----------------|-------------|---------------------|
| rkhunter | `rkhunter` | system | `apt install rkhunter` | 1.4 | rootkit |
| chkrootkit | `chkrootkit` | system | `apt install chkrootkit` | 0.55 | rootkit |
| lynis | `lynis` | system | `apt install lynis` | 3.0 | _(planned: system audit)_ |
| ClamAV | `clamscan` | malware | `apt install clamav` | 0.103 | _(planned: malware)_ |
| gitleaks | `gitleaks` | secrets | `go install github.com/gitleaks/gitleaks/v8@latest` | 8.0 | credentials |
| trufflehog | `trufflehog` | secrets | `go install github.com/trufflesecurity/trufflehog/v3@latest` | 3.0 | credentials |
| trivy | `trivy` | dependencies | `apt install trivy` or curl install | 0.40 | supply_chain |
| grype | `grype` | dependencies | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh` | 0.60 | supply_chain |
| hadolint | `hadolint` | containers | wget from GitHub releases | 2.0 | containers |
| dockle | `dockle` | containers | `apt install dockle` | 0.4 | containers |
| ssh-audit | `ssh-audit` | ssh | `pip3 install ssh-audit` | 3.0 | ssh |
| semgrep | `semgrep` | code | `pip3 install semgrep` | 1.0 | _(planned: code analysis)_ |
| bandit | `bandit` | code | `pip3 install bandit` | 1.7 | _(planned: code analysis)_ |
| nmap | `nmap` | network | `apt install nmap` | 7.0 | _(planned: ports/network)_ |
| ss | `ss` | network | built-in on Linux (iproute2) | — | _(planned: connections)_ |
| aide | `aide` | filesystem | `apt install aide` | 0.17 | _(planned: file_integrity)_ |
| debsums | `debsums` | forensics | `apt install debsums` | 3.0 | package_manager |

---

## Per-Tool Details

### rkhunter

| Field | Value |
|-------|-------|
| Binary | `rkhunter` |
| Category | system |
| Install | `apt install rkhunter` |
| Version check | `rkhunter --version` |
| Min version | 1.4 |
| Used by | `rootkit` scanner (optional) |

**What it adds:** rkhunter performs signature-based detection of known rootkits, backdoors, and
local exploits across hundreds of check categories including kernel modules, hidden files, suspect
binaries, and SUID/SGID files. The native Go rootkit scanner checks `/proc/modules` patterns and
`/dev` anomalies; rkhunter cross-references a curated database of thousands of known-bad indicators
that the native scanner cannot replicate without embedding the same data.

---

### chkrootkit

| Field | Value |
|-------|-------|
| Binary | `chkrootkit` |
| Category | system |
| Install | `apt install chkrootkit` |
| Version check | `chkrootkit -V` |
| Min version | 0.55 |
| Used by | `rootkit` scanner (optional) |

**What it adds:** chkrootkit uses a different detection methodology from rkhunter — it runs shell
and C programs to test for the presence of specific rootkits by their observable behavioral
signatures (e.g., packet sniffer detection, `lastlog` tampering, hidden processes via signal
testing). Running both chkrootkit and rkhunter together increases coverage because they do not
share signature sets and catch different rootkit families.

---

### lynis

| Field | Value |
|-------|-------|
| Binary | `lynis` |
| Category | system |
| Install | `apt install lynis` |
| Version check | `lynis --version` |
| Min version | 3.0 |
| Used by | _(planned: system hardening audit)_ |

**What it adds:** lynis is a comprehensive Unix/Linux security auditing framework covering 300+
controls across kernel hardening, authentication, file permissions, network configuration, boot
security, PAM, and more. It produces a hardening index score and prioritised recommendations.
The native scanners cover overlapping areas individually, but lynis encodes decades of CIS Benchmark
and STIG knowledge into one pass, catching misconfigurations that would require dozens of separate
native checks.

---

### ClamAV (clamscan)

| Field | Value |
|-------|-------|
| Binary | `clamscan` |
| Category | malware |
| Install | `apt install clamav` |
| Version check | `clamscan --version` |
| Min version | 0.103 |
| Used by | _(planned: malware scanner)_ |

**What it adds:** ClamAV provides signature-based antivirus scanning against a continuously updated
database of malware, trojans, web shells, and exploit payloads. Native Go checks look for
behavioral indicators (suspicious processes, unexpected SUID binaries) but cannot match file
content against a malware signature database without embedding ClamAV's functionality. The
`freshclam` daemon keeps signatures current.

---

### gitleaks

| Field | Value |
|-------|-------|
| Binary | `gitleaks` |
| Category | secrets |
| Install | `go install github.com/gitleaks/gitleaks/v8@latest` |
| Version check | `gitleaks version` |
| Min version | 8.0 |
| Used by | `credentials` scanner (optional) |

**What it adds:** gitleaks scans git repositories including their full commit history for secrets
using 100+ built-in rules covering AWS, GCP, Azure, GitHub, Stripe, Twilio, and many other
providers. The native Go credentials scanner applies regex patterns only to current file content;
gitleaks additionally scans git history, staged changes, and can use a custom `.gitleaks.toml`
rule file for organisation-specific patterns.

---

### trufflehog

| Field | Value |
|-------|-------|
| Binary | `trufflehog` |
| Category | secrets |
| Install | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| Version check | `trufflehog --version` |
| Min version | 3.0 |
| Used by | `credentials` scanner (optional) |

**What it adds:** trufflehog uses entropy analysis combined with pattern matching and performs
active verification of discovered secrets against live APIs (AWS STS, GitHub, etc.) to distinguish
valid credentials from false positives. This verification capability is not present in the native
scanner or in gitleaks. trufflehog and gitleaks complement each other: gitleaks is faster for
broad sweeps, trufflehog is more accurate on ambiguous findings.

---

### trivy

| Field | Value |
|-------|-------|
| Binary | `trivy` |
| Category | dependencies |
| Install | `apt install trivy` or `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sh` |
| Version check | `trivy --version` |
| Min version | 0.40 |
| Used by | `supply_chain` scanner (required for CVE matching) |

**What it adds:** trivy scans filesystems, container images, and language-specific lock files
(go.sum, package-lock.json, Pipfile.lock, etc.) against the NVD, GitHub Advisory Database, and
OS vendor advisories. It provides CVE IDs, CVSS scores, fixed versions, and links to advisories.
Native Go dependency parsing can detect lock file presence and pinning issues, but cannot match
package versions against a CVE database without an embedded copy of trivy's data.

---

### grype

| Field | Value |
|-------|-------|
| Binary | `grype` |
| Category | dependencies |
| Install | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh -s -- -b /usr/local/bin` |
| Version check | `grype version` |
| Min version | 0.60 |
| Used by | `supply_chain` scanner (optional, complements trivy) |

**What it adds:** grype uses the Anchore vulnerability database and excels at scanning container
images by layer and matching OS packages with their distro-specific vulnerability data. It produces
structured JSON output compatible with SARIF and other reporting formats. Running grype alongside
trivy increases coverage because they use different underlying databases and sometimes catch
different CVEs for the same package.

---

### hadolint

| Field | Value |
|-------|-------|
| Binary | `hadolint` |
| Category | containers |
| Install | `wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint` |
| Version check | `hadolint --version` |
| Min version | 2.0 |
| Used by | `containers` scanner (required for Dockerfile linting) |

**What it adds:** hadolint statically lints Dockerfiles against the Docker best-practice rule set
and shells out to ShellCheck for RUN instruction validation. It catches security-relevant issues
such as `apt-get install` without pinned versions, use of `latest` tags, missing `--no-install-recommends`,
running as root, adding secrets via ENV, and insecure curl/wget patterns. The native containers
scanner parses running container metadata; hadolint provides source-level Dockerfile analysis that
native parsing cannot do.

---

### dockle

| Field | Value |
|-------|-------|
| Binary | `dockle` |
| Category | containers |
| Install | `apt install dockle` (via Trivy apt repo) or GitHub releases |
| Version check | `dockle --version` |
| Min version | 0.4 |
| Used by | `containers` scanner (optional) |

**What it adds:** dockle checks built container images (not just Dockerfiles) against CIS Docker
Benchmark controls and Dockhero best practices. It inspects image layers, labels, entrypoints,
and filesystem contents for issues such as setuid binaries, world-writable files, and suspicious
layer additions. hadolint checks the source; dockle checks the resulting image — together they
cover both build-time and runtime container security.

---

### ssh-audit

| Field | Value |
|-------|-------|
| Binary | `ssh-audit` |
| Category | ssh |
| Install | `pip3 install ssh-audit` |
| Version check | `ssh-audit --version` |
| Min version | 3.0 |
| Used by | `ssh` scanner (optional) |

**What it adds:** ssh-audit performs active negotiation with the SSH daemon and evaluates the
supported key exchange algorithms, host key types, encryption ciphers, and MAC algorithms against
current security recommendations. It identifies deprecated algorithms (diffie-hellman-group1-sha1,
arcfour, MD5-based MACs, etc.) that the native sshd_config parser cannot detect by static analysis
alone, because the effective negotiated algorithm set depends on the OpenSSH version and
compile-time options.

---

### semgrep

| Field | Value |
|-------|-------|
| Binary | `semgrep` |
| Category | code |
| Install | `pip3 install semgrep` |
| Version check | `semgrep --version` |
| Min version | 1.0 |
| Used by | _(planned: code security analysis)_ |

**What it adds:** semgrep applies semantic pattern matching to source code across 30+ languages,
using community and commercial rule sets (including the `p/security-audit` and `p/owasp-top-ten`
packs) to detect injection vulnerabilities, insecure API usage, hardcoded secrets in code logic,
and framework-specific misconfigurations. Unlike grep-based pattern matching, semgrep understands
code structure (AST-aware), reducing false positives significantly.

---

### bandit

| Field | Value |
|-------|-------|
| Binary | `bandit` |
| Category | code |
| Install | `pip3 install bandit` |
| Version check | `bandit --version` |
| Min version | 1.7 |
| Used by | _(planned: Python code security analysis)_ |

**What it adds:** bandit is the standard Python security linter, checking for common vulnerabilities
such as use of `assert` in security checks, `subprocess` with `shell=True`, `pickle` deserialization,
weak cryptography (`md5`, `sha1`), SQL injection via string formatting, and insecure use of `yaml.load`.
It is Python-specific and complements semgrep (which is language-agnostic but less Python-aware
for library-specific patterns).

---

### nmap

| Field | Value |
|-------|-------|
| Binary | `nmap` |
| Category | network |
| Install | `apt install nmap` |
| Version check | `nmap --version` |
| Min version | 7.0 |
| Used by | _(planned: ports/network scanner)_ |

**What it adds:** nmap performs active port scanning with service and version detection (`-sV`)
and can run NSE scripts for vulnerability checks. The native Go ports scanner reads `/proc/net/tcp`
and `/proc/net/tcp6` to enumerate listening sockets on the local host; nmap adds active scanning
of a target from the network perspective (what is actually reachable from outside) and can scan
remote hosts, which `/proc` cannot provide.

---

### ss

| Field | Value |
|-------|-------|
| Binary | `ss` |
| Category | network |
| Install | Built-in on all modern Linux systems (iproute2 package) |
| Version check | `ss -V` |
| Min version | — |
| Used by | _(planned: connections scanner)_ |

**What it adds:** `ss` (socket statistics) is the modern replacement for `netstat`, providing
detailed socket information from the kernel including TCP state, send/receive queues, retransmit
counts, process associations, and cgroup membership. It can display UNIX domain sockets, raw
sockets, and netlink sockets that `/proc/net` files expose less cleanly. The native connections
scanner reads `/proc/net/tcp` directly; `ss` output provides a second verification path and
richer metadata.

---

### aide

| Field | Value |
|-------|-------|
| Binary | `aide` |
| Category | filesystem |
| Install | `apt install aide` |
| Version check | `aide --version` |
| Min version | 0.17 |
| Used by | _(planned: file_integrity scanner)_ |

**What it adds:** AIDE (Advanced Intrusion Detection Environment) maintains a cryptographic
database of filesystem state (hashes, permissions, ownership, inode numbers, extended attributes)
and detects changes since the database was last built. Checking against the AIDE database catches
modifications to system binaries, configuration files, and libraries that a rootkit might alter
after installation. The native file_integrity scanner performs real-time checks but has no
historical baseline; AIDE provides the baseline comparison capability.

---

### debsums

| Field | Value |
|-------|-------|
| Binary | `debsums` |
| Category | forensics |
| Install | `apt install debsums` |
| Version check | `debsums --version` |
| Min version | 3.0 |
| Used by | `package_manager` scanner (required for package integrity checking) |

**What it adds:** debsums verifies the MD5 checksums of all installed Debian package files against
the checksums recorded in the package's `.md5sums` control file. A modified system binary
(e.g., `/bin/ls` replaced by a rootkit) will produce a debsums mismatch. The native package_manager
scanner checks repository configuration and signing key validity; debsums adds post-install
tamper detection for the actual installed file contents.

---

## Installation Quick Reference

### apt-installable (run as root)

```bash
apt install -y rkhunter chkrootkit lynis clamav nmap aide debsums
```

Update ClamAV signatures after install:
```bash
freshclam
```

Initialise AIDE database after install:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### pip3-installable

```bash
pip3 install ssh-audit semgrep bandit
```

### Go-installable

```bash
go install github.com/gitleaks/gitleaks/v8@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
```

### curl/wget installs

```bash
# trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# hadolint
wget -O /usr/local/bin/hadolint \
  https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x /usr/local/bin/hadolint

# dockle (via trivy apt repo or GitHub releases)
VERSION=$(curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
curl -L "https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.tar.gz" | tar xz -C /usr/local/bin dockle
```
