---
name: plan
description: Convert an approved feature specification into an implementation and verification plan grounded in the current codebase. Use when the user invokes /plan or asks for a technical plan before coding.
---

# Plan

Read `.delivery/<feature-slug>/spec.md`. If it is absent or its gate is not
met, stop and route the work to `$spec`.

Create or update `.delivery/<feature-slug>/plan.md`.

## Workflow

1. Discover current architecture, symbols, callers, tests, and repository rules.
2. Map each acceptance criterion to implementation and verification work.
3. Choose the smallest coherent design that preserves existing boundaries.
4. Record:
   - status: `planned`;
   - current-state summary;
   - proposed design and data/control flow;
   - files and symbols expected to change;
   - API, DTO, schema, state, and compatibility effects;
   - ordered implementation slices;
   - unit, integration, build, smoke, and negative tests;
   - security/scope review points;
   - rollback or recovery considerations;
   - explicit non-goals and remaining decisions.
5. Identify steps requiring user authority, credentials, external coordination,
   destructive actions, publishing, or production access.

## Gate

Pass only when another agent could implement the plan without redesigning it.
Do not edit production code in this stage.
