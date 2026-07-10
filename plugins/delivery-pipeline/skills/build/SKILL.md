---
name: build
description: Implement an approved technical plan in bounded slices while preserving repository architecture, tests, and user changes. Use when the user invokes /build or authorizes implementation of an existing plan.
---

# Build

Read both `.delivery/<feature-slug>/spec.md` and `plan.md`. If either gate is
missing, stop and route to the earliest incomplete stage.

## Workflow

1. Confirm the worktree and preserve unrelated user changes.
2. Implement plan slices in order; keep product meaning in the owning layer.
3. Add or update focused tests with each behavior change.
4. Validate risky assumptions early with the narrowest relevant check.
5. Keep scope bounded to the accepted specification. Record necessary
   deviations in `plan.md` before proceeding.
6. Update status in `plan.md` to `built` only when implementation is complete.
7. Update durable architecture or decision docs only when a boundary or durable
   decision actually changed.

## Gate

Pass only when all planned behavior is implemented, no placeholder claims to be
functional, and focused tests pass. Do not tag, publish, deploy, or release.
