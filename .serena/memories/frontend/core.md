# Frontend
- React/TypeScript in `app/src`; Tauri 2 IPC via `invoke` and `listen`.
- `App.tsx` orchestrates workflow/target selection, structured runs, command preview, live output and cancellation.
- Live events use `probe-live-output` and must be filtered by `run_id`.
- Browser-only fallback data exists for absent Tauri runtime; backend DTOs remain authoritative in desktop runtime.
- Frontend build runs from `app/`.