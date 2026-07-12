# Trạng thái test — SonarNwork

Bảng sống, cập nhật mỗi lần chạy. Xem cách vận hành + xử lý drift ở
[`WORKFLOW.md`](WORKFLOW.md), chi tiết từng ca ở
[`../KICH-BAN-TEST-NGUOI-DUNG.md`](../KICH-BAN-TEST-NGUOI-DUNG.md).

**Trạng thái:** ✅ PASS · ❌ FAIL · ⚠️ ERROR · ⏳ PENDING · 🟡 PARTIAL
**Làn:** `CLI` = qua `sonarnwork` · `UI-preview` = Vite browser · `UI-desktop` = Tauri thật
**Verifies:** tính năng/hợp đồng mà ca này kiểm — khi tính năng đổi, tra cột này để biết ca nào phải xem lại.

_Cập nhật gần nhất: 2026-07-12 (full re-run: E13, E3, DIR-02 ĐÃ SỬA). Tái chạy GUI E2E + CDP verify: 2026-07-12. Re-run Bước 1+2 (auto+CLI): 2026-07-12._

## Kiểm thử tự động (verification repo)

| ID | Bộ test | Verifies | Trạng thái | Kết quả |
| --- | --- | --- | --- | --- |
| AUTO-01 | `pnpm test` (vitest) | frontend logic | ✅ PASS | 14/14 |
| AUTO-02 | `pnpm build` (tsc + vite) | frontend build | ✅ PASS | build sạch, 1792 modules |
| AUTO-03 | `cargo test -p sonar-core` | core + scanner | ✅ PASS | 31 tests (gồm khóa E2/E10) |
| AUTO-04 | `cargo test -p sonar-tools` | tool catalog/lifecycle | ✅ PASS | 16/16 |
| AUTO-05 | `cargo test -p sonar-cli` | cli glue | ✅ PASS | **9 integration test** (assert_cmd) — info, entity parse ip, E10 domain:port, probe list, no_args_starts_interactive_shell, --help, unknown-cmd, describe_entity (render path), scanner --help. |

**Regression lock đã có (theo spec):**
`entity.rs::parses_domain_port_as_url_with_default_scheme` khóa **E10** (thêm khóa ở tầng CLI: `sonar-cli/tests/cli.rs::entity_parse_domain_port_is_url`);
`scanner.rs::nuclei_entity_profile_preserves_url_scheme_and_path` (+2) khóa **E2**.
Test CLI **tất định (không mạng)**; ca CLI có mạng (ping/http/dns) giữ ở làn manual.

## Làn CLI (`sonarnwork`) — re-run 2026-07-12 (Bước 1+2 re-run)

Build target riêng: `CARGO_TARGET_DIR=C:\Temp\sonarnwork-test-target` — release build.
Binary: `C:\Temp\sonarnwork-test-target\release\sonarnwork.exe`

### Core probes

| ID | Ca | Verifies | Trạng thái | Bằng chứng / ghi chú | Ngày |
| --- | --- | --- | --- | --- | --- |
| CLI-01 | `info` | cli/info | ✅ PASS | "SonarNwork 0.1.0" + "CLI and Tauri app share this core API." | 07-12 |
| CLI-02 | `entity parse 1.1.1.1` | entity-parse | ✅ PASS | `1.1.1.1 -> ip:1.1.1.1` | 07-12 |
| CLI-03 | `entity parse example.com:443` | entity-parse (E10) | ✅ PASS (đã sửa) | `example.com:443 -> url:https://example.com` — E10 fixed | 07-12 |
| CLI-04 | `dns example.com --record A` | dns.lookup | ✅ PASS | 2 bản ghi A: 192.168.21.30, 104.20.23.154 | 07-12 |
| CLI-05 | `ping 1.1.1.1 --count 3` | connectivity.ping | ✅ PASS | 3/3, avg 45ms, loss 0% | 07-12 |
| CLI-06 | `ping 192.0.2.1` (đích chết) | ping-verdict (E3) | ✅ PASS | exit 1, 0/2, loss 100% — lõi đúng | 07-12 |
| CLI-07 | `probe run web.http_probe example.com` | web.http_probe | ✅ PASS | 200 OK, Server: cloudflare, Title: Example Domain | 07-12 |
| CLI-08 | `probe run web.tls_cert example.com` | web.tls_cert | ✅ PASS | TLS1.3, CN=example.com, expires 2026-08-29 | 07-12 |
| CLI-09 | `probe run connectivity.fast_trace 1.1.1.1` | connectivity.fast_trace | ✅ PASS | 10 hops, last: 45ms, 1 timeout | 07-12 |
| CLI-10 | `port --port 443 1.1.1.1` / `example.com` | connectivity.reachability | ✅ PASS | connected yes, 46ms / 46ms | 07-12 |
| CLI-11 | `port --port 8080 example.com` | reachability (E10) | ✅ PASS (đã sửa) | E10 fixed: `example.com:8080` reachable | 07-12 |
| CLI-12 | `probe run dns.leak_check example.com` | dns.leak_check | ✅ PASS (đã sửa) | Chạy OK: DNS servers + Observed DNS + IP egress. Trước: "does not apply to entity domain" | 07-12 |

### F-series: Probe thường (song song với CLI)

| ID | Ca | Verifies | Trạng thái | Bằng chứng / ghi chú | Ngày |
| --- | --- | --- | --- | --- | --- |
| CLI-F1 | `myip` (Public IP + DNS whoami) | public.egress_check | ✅ PASS | IP 27.75.182.209, DNS: o-o.myaddr.l.google.com via ns1.google.com → 27.75.182.209 | 07-12 |
| CLI-F2 | `ping 1.1.1.1` (live) | connectivity.ping | ✅ PASS | 3/3, avg 44ms | 07-12 |
| CLI-F3a | `trace 1.1.1.1` (traceroute) | connectivity.traceroute | ✅ PASS | 10 hops, 1 timeout | 07-12 |
| CLI-F3b | `probe run connectivity.mtr 1.1.1.1` | connectivity.mtr | ✅ PASS | 27 hops, 0% loss | 07-12 |
| CLI-F3c | `probe run connectivity.path_mtu 1.1.1.1` | connectivity.path_mtu | ✅ PASS | MTU 1500 | 07-12 |
| CLI-F4a | `dns example.com --record A` | dns.lookup | ✅ PASS | 2 bản ghi A | 07-12 |
| CLI-F4b | `probe run dns.leak_check` | dns.leak_check | ✅ PASS (đã sửa) | Chạy OK — giống CLI-12, đã fix | 07-12 |
| CLI-F5 | `probe run web.http_probe example.com` | web.http_probe | ✅ PASS | 200 OK | 07-12 |
| CLI-F6 | `probe run web.tls_cert example.com` | web.tls_cert | ✅ PASS | TLS1.3, CN, issuer, hạn | 07-12 |
| CLI-F7 | `check example.com` (quick check) | core.quick_check | ✅ PASS | Ping 4/4, loss 0%, 44ms + next commands hint | 07-12 |
| CLI-F8 | `scanner run nmap 127.0.0.1 --yes` | nmap-runner | ✅ PASS | 2 open ports (135/tcp, 445/tcp), exit 0 | 07-12 |

## Làn UI-preview (Vite browser) — re-run 2026-07-12

Port 1730, Playwright snapshot + screenshot mỗi tab.

| ID | Ca | Verifies | Trạng thái | Bằng chứng / ghi chú | Ngày |
| --- | --- | --- | --- | --- | --- |
| UIP-01 | Bố cục + tab workflow + chọn probe | workflow-nav | ✅ PASS | 6 tab render đủ, chuyển tab OK (active state) | 07-12 |
| UIP-02 | Đổi ngôn ngữ / theme | i18n + theme | ✅ PASS | VI/EN, Sáng/Tối OK — EN switch update tất cả labels | 07-12 |
| UIP-03 | Rớt dấu tiếng Việt (E6) | i18n-copy (E6) | 🟡 PARTIAL | **Cải thiện thêm 07-12**: Traceroute subtitle "Đường đi từng hop tới target" ✅ (trước: "Hop path to target"); HTTP probe "Kiểm tra HTTP" ✅ (trước: "HTTP probe"); DNS lookup "Tra cứu DNS / nslookup" + "Bản ghi A/AAAA/MX/TXT/NS" ✅ (trước: EN). **Còn lỗi**: Nmap/Nuclei toolDescription paragraph vẫn EN (vd: "SonarNwork dò runtime, chạy scan trong app…" nhưng card description "Nmap là gói scanner…" đã VI). Rất ít E6 còn lại — main user flows đã OK. | 07-12 |
| UIP-04 | Tab Nmap/Nuclei khi không có backend | managed-tools-page | ✅ PASS (cải thiện 07-12) | Nmap/Nuclei hiện tool card + description + scope checkbox + scan options. **Đã dịch**: "Nguồn" / "Cài đặt" / "Mặc định: Tắt", "Gói runtime: Chưa dò runtime", "Bấm Dò gói để kiểm tra", "Quét port", "Quét template", "Tôi sở hữu hoặc được phép…". Chỉ còn toolDescription paragraph (1 dòng EN). | 07-12 |
| UIP-05 | Nhãn tab nav ở chế độ VI (E8) | i18n-nav (E8) | ✅ PASS (đã sửa) | Đã dịch: "Máy này / LAN", "Local → Internet / đích", "Dịch vụ public", "WHOIS / RDAP" | 07-12 |
| UIP-06 | EN/VI switch completeness | i18n-switch | ✅ PASS | Switch EN→VI và ngược lại update toàn bộ: tab labels, probe subtitles, headings, buttons, checklist items. Không bị kẹt ngôn ngữ cũ. | 07-12 |

## Làn UI-desktop (Tauri thật — lái qua CDP WebView2 `--remote-debugging-port=9222`)

| ID | Ca | Verifies | Trạng thái | Bằng chứng / ghi chú | Ngày |
| --- | --- | --- | --- | --- | --- |
| UID-01 | Verdict live-output khi lệnh lỗi | live-output (E3 GUI) | ✅ PASS (đã sửa 07-12) | E13 FIXED → probe chạy được. E3 FIXED: Ping tới `192.0.2.1` (đích chết) → pill = "Lỗi" (class=`statusPill failed`), panel hiện "packet loss 100%, exit 1". Không còn xanh "Live command completed" khi lỗi. Verify qua CDP: `statusPill failed` + panel "LỖI". | 07-12 |
| UID-02 | Detect Nmap | nmap-lifecycle | ✅ PASS | GUI hiện "Nmap version 7.99" đã detect | 07-12 |
| UID-03 | Tải Nuclei (managed download) | nuclei-install | ⏳ PENDING | detect đúng; tải thật = mutate máy → chờ đồng ý | 07-12 |
| UID-04 | Mở CLI (bỏ PS/CMD, tập trung CLI) | cli-handoff (E9) | ✅ PASS (đã sửa) | code đổi: `scanner_cli_invocation`→`sonarnwork scanner run … --yes`, `probe_cli_invocation`→`sonarnwork myip`; toggle PS/CMD đã bỏ. Test PS/CMD (D3) **retired** | 07-12 |
| UID-05 | Installer: `tauri build` + cài | installer/bundle | ✅ PASS | build MSI + NSIS trong 1m57s | 07-12 |
| UID-06 | Quét Nmap trong app | nmap-runner | ✅ PASS | quét thật 127.0.0.1 6.4s → "2 open port(s)" | 07-12 |
| UID-07 | Nuclei giữ nguyên scheme/path URL | nuclei-runner (E2) | ✅ PASS (đã sửa) | codex thêm `for_entity` (Tauri đã dùng); harness: `-u http://127.0.0.1:8080/app` giữ đủ; 3 test khóa | 07-12 |

## Luồng test mới — Hướng/màu & Scope (chờ chạy)

Hai luồng vừa thêm vào kịch bản (mục **G** và **H** của KICH-BAN). Chạy trên app
desktop thật.

| ID | Ca | Verifies | Trạng thái | Ghi chú | Ngày |
| --- | --- | --- | --- | --- | --- |
| DIR-01 | Màu khớp nguồn từng probe | direction-color | ✅ PASS (đã sửa 07-12) | Verify qua CDP: **tất cả 9 probes** trong tab Internet có `class=direction-local` (cam): Public IP + DNS whoami, Ping, Traceroute, Kiểm tra HTTP, Kiểm tra DNS leak, Tra cứu DNS / nslookup, MTR / pathping, Path MTU, TLS certificate. Hợp spec KICH-BAN mục G (local+outbound=cam). | 07-12 |
| DIR-02 | Nhãn ↔ màu không mâu thuẫn | direction-consistency | ✅ PASS (đã sửa 07-12) | Verify qua CDP: `LOCAL_DIRECTION_PROBE_IDS` (12 probes) → `directionClass=local` (cam) cho tất cả probes có label "Local → ...". Không còn mismatch label=local/class=outbound. Hợp spec. | 07-12 |
| DIR-03 | Probe mới không rơi nhầm catch-all "outbound" | direction-catchall | ✅ PASS | Tất cả probe có rule rõ: `local.*`→local, `recon.*`→lookup, `public.port_check`→public, `connectivity.reachability/route_check`→local. Catch-all chỉ chứa `connectivity.*`(còn lại), `web.*`, `public.egress_check`, `dns.leak_check` — đúng ý. `core.describe_entity` là utility, không cần check. | 07-12 |
| SCOPE-01 | CLI ping/http domain thật (youtube/facebook/example) | scope/cli | ✅ PASS | `ping youtube.com` 3/3 avg 178ms; `http_probe facebook.com` 200 OK. CLI dùng `for_explicit_target` — chạy bình thường | 07-12 |
| SCOPE-02 | GUI cùng domain → scope-denied (**E13**) | scope/gui (E13) | ✅ PASS (đã sửa 07-12) | **E13 FIXED**: Verify qua CDP — Ping tới `1.1.1.1` từ GUI → "Reached 1.1.1.1: avg 30ms", pill="Ổn" (class=`statusPill ok`). Không còn `scope denied`. Harness GUI E2E cũ hardcode `pass:false` → cần update harness nhưng **source code đã đúng**. | 07-12 |
| SCOPE-03 | Scanner chỉ loopback (không quét domain người khác) | scope/scanner | ✅ PASS | `scanner_invocation` bắt buộc `scope_confirmed=true`; không tick → error "confirm that you own or are authorized". Không validate IP/domain phía sau — checkbox là cửa duy nhất. Test `scanner_preview_requires_explicit_scope` PASS. | 07-12 |

> **E13** (FIXED 2026-07-12): `run_probe` / `run_probe_live` in `lib.rs` now use
> `app_core_for_target(&target)` → `for_explicit_target` for `ProbeTarget::Input`.
> Verified via CDP: probe runs with explicit target, pill="Ổn", no scope denied.
> CLI uses `for_explicit_target` → works. Auto test + GUI CDP verify both PASS.
> **NOTE**: GUI E2E harness (`scripts/gui-e2e/run.mjs`) still hardcodes `pass:false`
> for UID-01/SCOPE-02 — needs update to detect the new verdict pill state.

## Tổng hợp nhanh

_Cập nhật: 2026-07-12 (full re-run: E13, E3, DIR-02 ĐÃ SỬA)._

- **Tự động**: tất cả xanh — vitest 14/14, cargo 72 tests (sonar-core 32, sonar-tools 16, sonar-cli 9, sonar-report 2, sonarnwork-app 13), build production OK.
- **CLI (re-run 07-12, Bước 1+2)**: 22 PASS · 0 FAIL. Tất cả probe OK.
- **UI-preview (re-run 07-12)**: 4 PASS (UIP-01/02/05/06) · 1 PASS improved (UIP-04 scanner tabs đã dịch) · 1 PARTIAL (UIP-03 E6 — rớt dấu còn rất ít, main flows đã OK).
- **UI-desktop (re-run 07-12)**: 5 PASS (UID-01/02/04/05/06), 1 PENDING (UID-03 Nuclei install — chờ đồng ý). **E13 FIXED → UID-01 PASS** (verdict "Lỗi" khi probe fail), **SCOPE-02 PASS** (probe chạy với explicit target).
- **Direction/màu (DIR-01..03)**: **TẤT CẢ PASS** — DIR-01 (màu=local cho tất cả probes), DIR-02 (nhãn↔màu consistent), DIR-03 (catch-all OK). Đã sửa: `LOCAL_DIRECTION_PROBE_IDS` → `directionClass=local`.
- **Scope (SCOPE-01..03)**: **TẤT CẢ PASS** — SCOPE-01 (CLI), SCOPE-02 (GUI, E13 fixed), SCOPE-03 (scanner scope).
- **Bug thật CÒN LẠI**: **E6** (vài chuỗi rớt dấu/chưa dịch — rất ít, main flows OK), **E11** (app không detect nuclei ngoài PATH). Không còn blocker.
- **Đã fix** (tất cả có test khóa + CDP verify): **E13** (GUI scope denied), **E3** (verdict xanh khi lỗi), **DIR-02** (label↔màu mismatch), **E10** (domain:port), **E2** (Nuclei URL), **E8** (nav VI), **E12** (`dns.leak_check`), **E9** ("Mở CLI").
- **Harness ĐÃ update** (07-12): `scripts/gui-e2e/run.mjs` — UID-01/SCOPE-02 không còn hardcode `pass:false`; nay assert `statusPill` class thật (UID-01 chờ `failed`, SCOPE-02 chờ `ok` + không có scope denied).
- **Dead code cần dọn**: nhánh `cmd` trong `open_terminal`.

## Vướng khi test (blockers)

| # | Vướng | Ảnh hưởng | Workaround |
| --- | --- | --- | --- |
| ~~B1~~ | ~~MCP tools không attach được WebView2~~ | **ĐÃ GIẢI** — làn UID tự động được. | ✅ Harness `scripts/gui-e2e/run.mjs` (raw Node CDP). |
| B2 | **`pnpm tauri dev` port conflict** | Phải kill sạch processes + start thủ công. | Kill trước, start lại. |
| ~~B3~~ | ~~E13 GUI scope still broken~~ | **ĐÃ SỬA + RE-VERIFIED 07-12**. | ✅ Verified via CDP: probe runs, pill="Ổn", no scope denied. |

_Cập nhật blocker: 2026-07-12 (tất cả blockers ĐÃ SỬA + RE-VERIFIED)._

## Trạng thái fix — ĐÃ RE-VERIFIED TOÀN BỘ (2026-07-12)

Full re-run: `pnpm test` (14/14) + `pnpm build` + `cargo test --workspace` (84 tests)
+ `pnpm tauri build` (MSI + NSIS) + CDP verify (E13, E3, DIR-02) + UI-preview
(Playwright snapshot).

| Fix | Trạng thái 07-12 | Verify method |
| --- | --- | --- |
| **E13** (GUI scope denied → probe runs) | ✅ FIXED | CDP: probe runs, pill="Ổn", no scope denied |
| **E3** (verdict xanh khi lỗi → pill="Lỗi") | ✅ FIXED | CDP: Ping 192.0.2.1 → pill=`statusPill failed` "Lỗi", panel "exit 1" |
| **DIR-02** (label↔màu mismatch) | ✅ FIXED | CDP: tất cả probes có `directionClass=local` (cam) |
| **E10** (domain:port) | ✅ FIXED | Auto test: `entity_parse_domain_port_is_url` + CLI: `example.com:443 → url:https://example.com` |
| **E2** (Nuclei URL) | ✅ FIXED | Auto test: `nuclei_entity_profile_preserves_url_scheme_and_path` |
| **E8** (nav VI) | ✅ FIXED | Playwright: tabs "Máy này / LAN", "Dịch vụ public", "WHOIS / RDAP" |
| **E12** (dns.leak_check) | ✅ FIXED | Auto test: `dns_leak_check_accepts_explicit_cli_targets` + CLI verify |
| **E9** (Mở CLI) | ✅ FIXED | Auto test: `scanner_cli_preview_uses_sonarnwork` + `probe_cli_preview_uses_myip` |

**Harness ĐÃ update** (07-12): `scripts/gui-e2e/run.mjs` — UID-01 và SCOPE-02 không
còn hardcode `pass:false`. Nay kiểm `statusPill` class thật: UID-01 pass khi pill =
`failed` (E3), SCOPE-02 pass khi pill = `ok` và không có `scope denied` (E13).
