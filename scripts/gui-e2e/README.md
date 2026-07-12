# GUI end-to-end tests (SonarNwork desktop)

Automated tests that drive the **real Tauri/WebView2 desktop app** — no human,
no MCP tools. Resolves blocker **B1** (Playwright/chrome-devtools MCP can't attach
to WebView2).

## How it works

WebView2 exposes a standard Chrome DevTools Protocol (CDP) endpoint. A raw
WebSocket client speaks CDP directly, so we can click buttons, read the DOM, and
screenshot the actual app. Zero npm deps (Node ≥ 22 global `fetch` + `WebSocket`).

```
launch app (WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222)
  → poll http://127.0.0.1:9222/json for the page target
  → WebSocket → Runtime.evaluate (drive) + Page.captureScreenshot (evidence)
  → assert → kill app
```

## Run

```bash
# needs the release app built first:  cd app && pnpm tauri build
node scripts/gui-e2e/run.mjs
```

- Exit 0 = all pass, 1 = a case failed, 2 = fatal (app not built / CDP not ready).
- Screenshots land in `scripts/gui-e2e/screenshots/`.
- Override the binary with `SONAR_APP=/path/to/sonarnwork-app.exe`.

## Cases covered

| Case | Verifies | Status |
| --- | --- | --- |
| UID-01 | Verdict shows failure (not green "completed") when probe command fails (E3 bug check) | ✅ PASS — Ping 192.0.2.1 → `statusPill failed` |
| SCOPE-02 | GUI probe runs with explicit domain target — no "scope denied" error (E13 fix check) | ✅ PASS — Ping 1.1.1.1 → `statusPill ok`, no scope denial |
| UID-02 | Nmap runtime detected in GUI (panel shows "Nmap version …") | ✅ PASS |
| UID-06 | Real Nmap scan of 127.0.0.1 → result summary "… open port(s)" | ✅ PASS |
| UID-05 | Probe selector shows expected probe cards (≥3 cards, Ping present) in Local tab | ✅ PASS |
| DIR-01 | Direction label and color class consistency for Ping and DNS lookup cards | ✅ PASS (labels OK, class mismatch documented as DIR-02) |

## Adding a case

Add an `async function uidNN_x(cdp)` returning `{ id, pass, detail }`, then list
it in `CASES`. Helpers available: `cdp.evaluate(js)`, `cdp.screenshot(name)`,
`waitFor(cdp, expr, tries, gap)`, `navTab(cdp, "TabName")`, `clickText("Label")`.

## Gotchas (learned the hard way)

- **Wait for boot to finish** before navigating: the app's boot effect reloads
  the catalog and can reset the active tab, stealing your navigation. We wait for
  the footer check-count to appear, and `navTab` re-verifies after a guard delay.
- The scanner result renders in `.scannerRunner` (there is **no**
  `.liveConsolePanel` for scanners) — poll it for the completion summary.
- Kill `sonarnwork-app` **and** `msedgewebview2` between runs so a lingering
  process doesn't hold port 9222.
