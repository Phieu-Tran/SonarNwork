---
name: review
description: Perform the QA and release-readiness gate by comparing code and verification evidence with the approved specification and plan. Use when the user invokes /review or requests a final code, security, or product review before release.
---

# Review

Read `spec.md`, `plan.md`, and `verification.md`. Inspect the actual diff
and relevant callers rather than trusting summaries. Create or update
`.delivery/<feature-slug>/review.md`.

## Workflow

1. Check every acceptance criterion and plan commitment against code and evidence.
2. Review correctness, regressions, compatibility, error handling, concurrency,
   cleanup, authorization/scope, command injection, secrets, and UX states.
3. Classify findings:
   - blocker: unsafe, data-loss, security, or unusable release;
   - major: acceptance failure or likely regression;
   - minor: bounded quality issue;
   - note: optional improvement.
4. Include exact file/symbol evidence and a concrete remediation for each finding.
5. Record status as `changes-required` or `reviewed`.

## Gate

Pass only with zero blocker and major findings, all required verification
evidence present, and known limitations explicitly documented. Review does not
authorize code changes, publishing, tagging, or deployment.
