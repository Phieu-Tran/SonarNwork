---
name: ship
description: Run final release gates, build and smoke-test distributable artifacts, and prepare a release handoff. Use when the user invokes /ship or explicitly asks to package, tag, publish, deploy, or release a reviewed change.
---

# Ship

Require a reviewed feature with passing verification. Create or update
`.delivery/<feature-slug>/release.md`.

## Workflow

1. Recheck clean release inputs, version, dependency lockfiles, release config,
   documented limitations, and artifact naming.
2. Run the required final test/build suite from a release configuration.
3. Build distributable artifacts and smoke-test the exact release binary/package.
4. Record artifact paths, sizes/checksums when useful, commands, test evidence,
   version, known limitations, and rollback/uninstall notes.
5. Set status to `packaged` after local artifacts pass.
6. Tag, push, upload, deploy, announce, or modify external systems only when the
   user explicitly authorizes that action. Record the resulting identifiers and
   set status to `shipped` only after the external action succeeds.

## Gate

Do not ship with blocker/major findings, failed required checks, unreviewed scope
changes, or untested artifacts. Local packaging is not equivalent to publishing.
