# Conventions
- Put product meaning, parsers, platform command construction, scope and interpretation in shared Rust, not shells.
- Every probe declares accurate status/risk/requirements and supported entity kinds.
- User command overrides are `ActionClass::ExternalTool`.
- Preserve structured summaries and raw evidence; shells may format but not reinterpret.
- Keep planned remote ingress distinct from local reachability; Globalping-style measurements are not public port checks.
- Use semantic symbol edits for whole functions/types and narrow patches for local changes.