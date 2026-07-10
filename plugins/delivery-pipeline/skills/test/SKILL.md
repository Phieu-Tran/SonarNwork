---
name: test
description: Verify an implementation against its specification, run proportional automated and smoke tests, diagnose failures, and produce a verification report. Use when the user invokes /test or asks to validate/debug a completed build.
---

# Test

Read the feature `spec.md` and `plan.md`. Create or update
`.delivery/<feature-slug>/verification.md`.

## Workflow

1. Derive the test matrix from acceptance criteria and changed surfaces.
2. Run focused tests first, then repository-required format, type, lint, build,
   workspace, integration, and smoke checks.
3. Exercise success, invalid input, permission/scope denial, cancellation,
   missing dependency, and recovery paths where relevant.
4. Diagnose failures to a concrete cause. Fix only when the user requested
   implementation/debugging; otherwise report without mutating code.
5. Record commands, environment-relevant facts, pass/fail results, failures,
   fixes, skipped checks with reasons, and remaining risk.
6. Set status to `verified` only when every required acceptance criterion has
   evidence and no required check is failing.

## Gate

Fail closed on missing required tests. A successful compile alone is not a
verification pass.
