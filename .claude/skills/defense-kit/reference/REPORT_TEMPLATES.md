# Report Templates

## Executive Summary

```
# Security Assessment — {hostname}
Date: {date}
Scanner: defense-kit v{version}

## Summary
- {total} findings: {critical} critical, {high} high, {medium} medium, {low} low
- Top risks: {top 3 critical findings}
- Recommended actions: {top 3 remediations}

## Risk Level: {CRITICAL|HIGH|MEDIUM|LOW}
```

## Detailed Findings Report

```
# Detailed Security Findings — {hostname}

## Critical Findings
### {finding.title}
- **Scanner**: {finding.scanner}
- **Location**: {finding.location}
- **Evidence**: {finding.evidence}
- **Remediation**: {finding.remediation}
- **References**: {finding.references}

(repeat per finding, grouped by severity)
```

## Compliance Report (CIS)

```
# CIS Benchmark Compliance — {hostname}
Framework: CIS Benchmarks for Linux
Date: {date}

## Summary
- Controls assessed: {total}
- Passed: {passed} ({percent}%)
- Failed: {failed}
- Not assessed: {not_assessed}

## Failed Controls
### {control.id}: {control.title}
- Section: {control.section}
- Finding: {finding.title}
- Severity: {finding.severity}
- Remediation: {finding.remediation}
```

## Incident Response Report

```
# Incident Response — {hostname}
Date: {date}
Triggered by: {initial finding}

## Timeline
{timestamp} — {event description}

## Attack Chain
{chain description with confidence score}

## Indicators of Compromise
- IPs: {list}
- Files: {list}
- Processes: {list}

## Actions Taken
1. {action}

## Recommendations
1. {recommendation}
```
