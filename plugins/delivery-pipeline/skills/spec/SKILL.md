---
name: spec
description: Refine an idea, feature request, bug report, or product change into a scoped specification with acceptance criteria. Use when the user invokes /spec or asks to define requirements before implementation.
---

# Spec

Create or update `.delivery/<feature-slug>/spec.md`. Use a stable lowercase
hyphenated slug. Reuse an existing feature folder when the request continues an
active feature.

## Workflow

1. Inspect current behavior and relevant constraints before writing requirements.
2. Separate the user problem from a proposed solution.
3. Resolve ambiguities that materially change scope; otherwise make and label a
   conservative assumption.
4. Write:
   - status: `specified`;
   - problem and desired outcome;
   - users and primary flow;
   - in-scope and out-of-scope behavior;
   - functional and non-functional requirements;
   - security, privacy, authorization, and destructive-action constraints;
   - measurable acceptance criteria;
   - dependencies, risks, and open questions.
5. Ensure every acceptance criterion is observable and testable.

## Gate

Pass only when scope, exclusions, and acceptance criteria are unambiguous enough
to plan. Do not design files or implementation steps here. Report the artifact
path and any unresolved blocker.
