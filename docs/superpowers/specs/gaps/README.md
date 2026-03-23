# Defense-Kit v2 — Gap Analysis & Improvement Specs

Post-implementation audit of defense-kit v2. Documents what's missing, what's weak, and what needs to be built to make this a real defensive security tool.

## Documents

| Spec | Priority | Description |
|------|----------|-------------|
| [01-stub-scanners.md](01-stub-scanners.md) | CRITICAL | 13 empty stub scanners that detect nothing |
| [02-detection-quality.md](02-detection-quality.md) | CRITICAL | Weaknesses in existing real scanners |
| [03-missing-capabilities.md](03-missing-capabilities.md) | HIGH | Entire capability areas not covered |
| [04-hardener-gaps.md](04-hardener-gaps.md) | HIGH | 3 of 4 hardeners are empty stubs |
| [05-testing-gaps.md](05-testing-gaps.md) | HIGH | Coverage holes and missing test types |
| [06-architecture-improvements.md](06-architecture-improvements.md) | MEDIUM | Structural improvements for real-world use |
| [07-prioritized-roadmap.md](07-prioritized-roadmap.md) | — | Ordered implementation plan to fix everything |

## Current State Summary

- **18 of 31 scanners are real** (58%) — 13 are empty stubs
- **1 of 4 hardeners works** (25%) — only SSH
- **~60% detection coverage** on a compromised server
- **~40% of the spec's 30 scan categories** have no detection logic
