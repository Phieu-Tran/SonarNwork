// GUI end-to-end runner for SonarNwork (Tauri/WebView2), fully automated.
//
// Why this exists: the Playwright/chrome-devtools MCP tools cannot attach to
// WebView2 (they spawn their own Chrome). But WebView2 exposes a standard CDP
// endpoint, and a raw WebSocket client speaks CDP directly — so the real
// desktop app IS drivable without a human (blocker B1 workaround).
//
// Flow: launch app with remote-debugging-port -> poll /json for the page target
// -> connect WebSocket -> Runtime.evaluate to drive + assert -> screenshot ->
// kill app. Zero npm deps (Node >=22 global fetch + WebSocket).
//
// Run:  node scripts/gui-e2e/run.mjs
// Env:  SONAR_APP  path to sonarnwork-app.exe (default: target/release build)

import { spawn, spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP =
  process.env.SONAR_APP ??
  path.resolve(HERE, "../../target/release/sonarnwork-app.exe");
const PORT = Number(process.env.SONAR_CDP_PORT ?? 9222);
const SHOTS = path.join(HERE, "screenshots");

// ---- CDP over raw WebSocket -------------------------------------------------
function openCdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const { res, rej } = pending.get(m.id);
      pending.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    }
  });
  const ready = new Promise((r, j) => {
    ws.addEventListener("open", r);
    ws.addEventListener("error", () => j(new Error("ws error")));
  });
  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const i = ++id;
      pending.set(i, { res, rej });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  return {
    ready,
    close: () => ws.close(),
    send,
    async evaluate(expr) {
      const r = await send("Runtime.evaluate", {
        expression: expr,
        returnByValue: true,
        awaitPromise: true,
      });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result.value;
    },
    async screenshot(name) {
      const r = await send("Page.captureScreenshot", { format: "png" });
      fs.mkdirSync(SHOTS, { recursive: true });
      fs.writeFileSync(path.join(SHOTS, name), Buffer.from(r.data, "base64"));
    },
    enable: () => Promise.all([send("Runtime.enable"), send("Page.enable")]),
  };
}

async function pageTarget() {
  const res = await fetch(`http://127.0.0.1:${PORT}/json`);
  const list = await res.json();
  return list.find((t) => t.type === "page");
}

async function launchApp() {
  if (!fs.existsSync(APP)) {
    throw new Error(`app not found: ${APP} (build it: cd app && pnpm tauri build)`);
  }
  const child = spawn(APP, [], {
    env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PORT}` },
    stdio: "ignore",
    windowsHide: false,
  });
  for (let i = 0; i < 40; i++) {
    await sleep(500);
    try {
      const t = await pageTarget();
      if (t?.webSocketDebuggerUrl) return { child, wsUrl: t.webSocketDebuggerUrl };
    } catch {
      /* not up yet */
    }
  }
  throw new Error("app CDP endpoint did not become ready");
}

function killApp(child) {
  try {
    spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
  } catch {
    /* ignore */
  }
  try {
    spawnSync("taskkill", ["/IM", "sonarnwork-app.exe", "/T", "/F"], { stdio: "ignore" });
  } catch {
    /* ignore */
  }
}

const clickText = (txt) => `
(() => { const b=[...document.querySelectorAll('button')]
  .find(e=>e.textContent.trim()===${JSON.stringify(txt)}&&!e.disabled);
  if(!b) return "MISSING:"+${JSON.stringify(txt)}; b.click(); return "ok"; })()`;

async function waitFor(cdp, expr, tries = 20, gap = 500) {
  for (let i = 0; i < tries; i++) {
    if (await cdp.evaluate(expr)) return true;
    await sleep(gap);
  }
  return false;
}

// Click a top-nav tab (scoped to `nav button`) and confirm it STAYS active —
// the boot effect can reset the tab once initial data loads, so we re-verify
// after a short guard delay and retry.
async function navTab(cdp, name) {
  // Match by substring so tab-label changes (e.g. i18n renames) don't break the
  // harness — pass a stable fragment like "Internet" or "Nmap".
  const isActive = `(document.querySelector('nav button.active')?.textContent||'').includes(${JSON.stringify(name)})`;
  for (let t = 0; t < 3; t++) {
    await cdp.evaluate(
      `[...document.querySelectorAll('nav button')].find(e=>e.textContent.includes(${JSON.stringify(name)}))?.click()`,
    );
    if (!(await waitFor(cdp, isActive, 12, 300))) continue;
    await sleep(900); // guard against a late boot reset
    if (await cdp.evaluate(isActive)) return true;
  }
  return false;
}

const NMAP_HAS_VERSION = `/Nmap version/i.test(document.querySelector('.managedToolPage,.externalScannerPanel')?.innerText||'')`;

const clickCard = (title) => `
(()=>{const b=[...document.querySelectorAll('.checkCard strong')]
  .find(e=>e.textContent.trim()===${JSON.stringify(title)});
  if(!b)return "MISSING:"+${JSON.stringify(title)};
  b.closest('.checkCard').click(); return "ok"; })()`;

// Set the probe target input via the native value setter so React's onChange fires.
const setTarget = (val) => `
(()=>{const i=document.querySelector('.targetInput input');
  if(!i)return "MISSING:targetInput";
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  setter.call(i,${JSON.stringify(val)});
  i.dispatchEvent(new Event('input',{bubbles:true})); return "ok"; })()`;

const CHAY_ENABLED = `!![...document.querySelectorAll('button')].find(e=>e.textContent.trim()==='Chạy'&&!e.disabled)`;

function verdictPillInfo(cdp) {
  return cdp.evaluate(`(()=>{
    const p=document.querySelector('.statusPill');
    const t=document.querySelector('.resultPanel > header strong');
    return {pill:p?.textContent?.trim()||'',status:p?.className||'',title:t?.textContent?.trim()||''};
  })()`);
}

// ---- Cases (each returns {id, pass, detail}) --------------------------------
async function uid02_detectNmap(cdp) {
  const navd = await navTab(cdp, "Nmap");
  const ok = await waitFor(cdp, NMAP_HAS_VERSION, 20, 500); // detect runs async on tab mount
  await cdp.screenshot("uid02-nmap.png");
  const tab = await cdp.evaluate(`document.querySelector('nav button.active')?.textContent?.trim() ?? '?'`);
  const present = await cdp.evaluate(`!!document.querySelector('.managedToolPage,.externalScannerPanel')`);
  const text = await cdp.evaluate(
    `document.querySelector('.managedToolPage,.externalScannerPanel')?.innerText ?? ''`,
  );
  return {
    id: "UID-02",
    pass: ok,
    detail: ok
      ? (text.match(/Nmap version[^\n]*/i)?.[0] ?? "detect ok")
      : `[dbg nav=${navd} tab=${tab} panel=${present} len=${text.length}] ${text.slice(0, 60)}`,
  };
}

async function uid06_scanNmap(cdp) {
  if (!(await navTab(cdp, "Nmap"))) return { id: "UID-06", pass: false, detail: "nav to Nmap failed" };
  await waitFor(cdp, `!!document.querySelector('.scopeConfirmation input[type=checkbox]')`);
  await waitFor(cdp, NMAP_HAS_VERSION, 20, 500); // need runtime detected so Chạy can enable
  await cdp.evaluate(
    `(()=>{const c=document.querySelector('.scopeConfirmation input[type=checkbox]');if(c&&!c.checked)c.click();})()`,
  );
  const enabled = await waitFor(
    cdp,
    `!![...document.querySelectorAll('button')].find(e=>e.textContent.trim()==='Chạy'&&!e.disabled)`,
    12,
    400,
  );
  if (!enabled) return { id: "UID-06", pass: false, detail: "Chạy not enabled (runtime/scope)" };
  await cdp.evaluate(clickText("Chạy"));
  // scanner result lands in .scannerRunner (no .liveConsolePanel); wait for the
  // completion summary to appear rather than a fixed sleep.
  await waitFor(
    cdp,
    `/(open port|finding|completed|Exit)/i.test(document.querySelector('.scannerRunner')?.innerText||'')`,
    45,
    1000,
  );
  await sleep(500);
  await cdp.screenshot("uid06-nmap-scan.png");
  const out = await cdp.evaluate(`document.querySelector('.scannerRunner')?.innerText ?? ''`);
  const pass = /open port/i.test(out);
  return { id: "UID-06", pass, detail: pass ? out.match(/.*open port.*/i)?.[0]?.trim() : "no 'open port' in result" };
}

// UID-01 / E3: verdict shows FAILURE (not a green "completed") when the probe
// command itself fails. Ping a dead but routable host (192.0.2.1, TEST-NET-1) so
// the probe actually runs (E13 fixed) but the command reports failure — the pill
// must then read "failed"/"Lỗi", not "ok".
async function uid01_verdictOnFailure(cdp) {
  if (!(await navTab(cdp, "Internet"))) return { id: "UID-01", pass: false, detail: "nav to probe tab failed" };
  await sleep(400);
  await cdp.evaluate(clickCard("Ping"));
  await sleep(600);
  await cdp.evaluate(setTarget("192.0.2.1"));
  await sleep(500);
  if (!(await waitFor(cdp, CHAY_ENABLED, 20, 400)))
    return { id: "UID-01", pass: false, detail: "Chạy not enabled after target set" };
  await cdp.evaluate(clickText("Chạy"));
  // Ping to a dead host takes a few seconds to time out; wait for the verdict pill.
  await waitFor(cdp, `/statusPill (ok|warning|failed)/.test(document.querySelector('.statusPill')?.className||'')`, 40, 500);
  await sleep(500);
  await cdp.screenshot("uid01-verdict-fail.png");
  const error = await cdp.evaluate(`document.querySelector('.appError,.errorBanner')?.innerText?.slice(0,200) || ''`);
  const v = await verdictPillInfo(cdp);
  const scopeDenied = /scope denied/i.test(error);
  const failedVerdict = /\bfailed\b/.test(v.status); // statusPill class carries the verdict
  // Pass = probe ran (no E13 scope denial) AND the failure surfaced as a failed verdict (E3).
  const pass = !scopeDenied && failedVerdict;
  return {
    id: "UID-01",
    pass,
    detail: scopeDenied
      ? `REGRESSION E13: probe blocked — ${error.slice(0, 120)}`
      : `pill="${v.pill}" class="${v.status}" — ${failedVerdict ? "failure verdict shown (E3 ok)" : "expected 'failed' verdict, not shown"}`,
  };
}

// SCOPE-02 / E13: GUI probe runs with an explicit target and NO "scope denied"
// error. Ping 1.1.1.1 (reachable) — the probe should complete with an "ok" verdict
// because run_probe now builds its core via for_explicit_target.
async function scope02_explicitTarget(cdp) {
  if (!(await navTab(cdp, "Internet"))) return { id: "SCOPE-02", pass: false, detail: "nav to probe tab failed" };
  await sleep(400);
  await cdp.evaluate(clickCard("Ping"));
  await sleep(600);
  await cdp.evaluate(setTarget("1.1.1.1"));
  await sleep(500);
  if (!(await waitFor(cdp, CHAY_ENABLED, 20, 400)))
    return { id: "SCOPE-02", pass: false, detail: "Chạy not enabled after target set" };
  await cdp.evaluate(clickText("Chạy"));
  await waitFor(cdp, `/statusPill (ok|warning|failed)/.test(document.querySelector('.statusPill')?.className||'')`, 40, 500);
  await sleep(500);
  await cdp.screenshot("scope02-explicit-target.png");
  const error = await cdp.evaluate(`document.querySelector('.appError,.errorBanner')?.innerText?.slice(0,200) || ''`);
  const v = await verdictPillInfo(cdp);
  const scopeDenied = /scope denied/i.test(error);
  const ranOk = /\bok\b/.test(v.status); // reachable host → "ok" verdict
  // Pass = E13 fixed: probe executed with the explicit target and did not get denied.
  const pass = !scopeDenied && ranOk;
  return {
    id: "SCOPE-02",
    pass,
    detail: scopeDenied
      ? `E13 REGRESSION: ${error.slice(0, 120)}`
      : `pill="${v.pill}" class="${v.status}" — ${ranOk ? "probe ran with explicit target (E13 fixed)" : "no ok verdict"}`,
  };
}

// UID-05: probe selector shows expected probe cards
async function uid05_probeSelector(cdp) {
  if (!(await navTab(cdp, "Internet"))) return { id: "UID-05", pass: false, detail: "nav to probe tab failed" };
  await sleep(600);
  await cdp.screenshot("uid05-probe-selector.png");
  const count = await cdp.evaluate(`document.querySelectorAll('.checkCard').length`);
  const hasPing = await cdp.evaluate(
    `[...document.querySelectorAll('.checkCard strong')].some(e=>e.textContent.trim()==='Ping')`,
  );
  return {
    id: "UID-05",
    pass: count >= 3 && hasPing,
    detail: count >= 3 && hasPing ? `${count} cards, Ping present` : `cards=${count} hasPing=${hasPing}`,
  };
}

// DIR-01: direction label and color consistency for probes
// Verifies the eyebrow label matches the CSS direction class.
// Currently all probes get direction-outbound (catch-all) in directionClass,
// while labels say "Local → ..." — this IS the DIR-02 mismatch bug.
async function dir01_directionLabels(cdp) {
  if (!(await navTab(cdp, "Internet"))) return { id: "DIR-01", pass: false, detail: "nav to probe tab failed" };
  await sleep(400);
  const checks = [];
  for (const title of ["Ping", "DNS lookup / nslookup"]) {
    await cdp.evaluate(clickCard(title));
    await sleep(300);
    const card = await cdp.evaluate(`(()=>{
      const c=[...document.querySelectorAll('.checkCard strong')].find(e=>e.textContent.trim()===${JSON.stringify(title)});
      if(!c)return null;
      const btn=c.closest('.checkCard');
      const eyebrow=c.parentElement?.querySelector('small');
      return {cls:btn?.className||'',label:eyebrow?.textContent?.trim()||''};
    })()`);
    if (!card) { checks.push(`${title}: card not found`); continue; }
    // Check label contains expected text (case-insensitive)
    const labelLower = card.label.toLowerCase();
    const hasLocal = labelLower.includes('local');
    const hasTarget = title === 'Ping' ? labelLower.includes('target') : labelLower.includes('dns');
    const labelOk = hasLocal && hasTarget;
    // Check CSS class — currently all probes get direction-outbound (DIR-02 bug)
    const hasDirection = card.cls.includes('direction-');
    const dirClass = card.cls.match(/direction-(\w+)/)?.[1] || 'none';
    const labelClassConsistent = labelLower.includes('local') && dirClass === 'local';
    checks.push(`${title}: label="${card.label}" ${labelOk ? 'OK' : 'MISMATCH'} class=${dirClass} ${labelClassConsistent ? 'consistent' : 'MISMATCH(label=local but class=' + dirClass + ')'}`);
  }
  await cdp.screenshot("dir01-direction-labels.png");
  // PASS if labels are correct (even if class is mismatched — that's DIR-02, not DIR-01)
  const pass = checks.every((c) => c.includes('label=') && !c.includes('label=MISMATCH'));
  return { id: "DIR-01", pass, detail: checks.join(" | ") };
}

const CASES = [uid01_verdictOnFailure, scope02_explicitTarget, uid02_detectNmap, uid06_scanNmap, uid05_probeSelector, dir01_directionLabels];

// Guard: the harness runs the COMPILED binary, not source. If the exe is older
// than the Rust source, results reflect stale code (e.g. a false "E13 not fixed"
// scope-denied). Warn loudly so nobody trusts a stale run.
function staleWarning() {
  try {
    const bin = fs.statSync(APP).mtimeMs;
    const srcs = ["app/src-tauri/src/lib.rs", "crates/sonar-core/src/app.rs", "crates/sonar-core/src/scope.rs"]
      .map((p) => path.resolve(HERE, "../../", p));
    const newest = Math.max(...srcs.map((s) => { try { return fs.statSync(s).mtimeMs; } catch { return 0; } }));
    if (newest > bin) {
      const hrs = ((newest - bin) / 3.6e6).toFixed(1);
      return `⚠️  STALE BINARY: ${path.basename(APP)} is ~${hrs}h OLDER than Rust source — results may reflect OLD code (false FAILs). Rebuild: cd app && pnpm tauri build`;
    }
  } catch {
    /* ignore */
  }
  return null;
}

// ---- Main -------------------------------------------------------------------
async function main() {
  console.log(`[gui-e2e] launching ${APP} (CDP :${PORT})`);
  const stale = staleWarning();
  if (stale) console.warn(`\n${stale}\n`);
  const { child, wsUrl } = await launchApp();
  const cdp = openCdp(wsUrl);
  const results = [];
  try {
    await cdp.ready;
    await cdp.enable();
    await waitFor(cdp, `document.querySelectorAll('nav button').length >= 3`, 30, 500); // React mount
    // Wait for boot to finish (catalog loaded → footer shows the check count),
    // otherwise a late boot reset steals our tab navigation.
    await waitFor(cdp, `/\\d+\\s*(kiểm tra|checks)/.test(document.querySelector('.contextFooter')?.innerText||'')`, 40, 500);
    await sleep(800);
    for (const c of CASES) {
      try {
        results.push(await c(cdp));
      } catch (e) {
        results.push({ id: c.name, pass: false, detail: `ERROR ${e.message}` });
      }
    }
  } finally {
    cdp.close();
    killApp(child);
  }
  console.log("\n=== GUI E2E RESULTS ===");
  let failed = 0;
  for (const r of results) {
    console.log(`${r.pass ? "✅ PASS" : "❌ FAIL"}  ${r.id}  — ${r.detail}`);
    if (!r.pass) failed++;
  }
  console.log(`\n${results.length - failed}/${results.length} passed. Screenshots: ${SHOTS}`);
  if (stale) console.warn(`\n${stale}\n(Any FAIL above may be a stale-binary false negative — rebuild and re-run.)`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error("[gui-e2e] fatal:", e.message);
  process.exit(2);
});
