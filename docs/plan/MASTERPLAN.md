# MASTERPLAN — Bản đồ thực thi toàn repo SonarNwork

> **File này để làm gì.** Nó là **danh sách đề bài đã bẻ nhỏ và xếp thứ tự** cho
> toàn bộ việc còn lại của repo. Orchestrator (xem [`../agents/orchestrator.md`](../agents/orchestrator.md))
> đọc file này để biết **làm task nào tiếp theo**, rồi mới sinh ra một
> `docs/plan/<ten-task>.md` chi tiết cho worker chạy một vòng lặp.
>
> - ROADMAP (`../ROADMAP.md`) = **NÓI CÁI GÌ** cho người dùng (bản đồ tính năng).
> - MASTERPLAN (file này) = **LÀM THEO THỨ TỰ NÀO**, mỗi bước là một đề chạy được.
> - `docs/plan/<task>.md` = **ĐỀ CHI TIẾT** một vòng (mục tiêu + acceptance).
> - `docs/plan/REPORT-<task>.md` = worker báo cáo lại.
>
> **Nguồn sự thật là code, không phải file này.** Trước khi bắt đầu một task,
> orchestrator PHẢI đọc lại code/test hiện tại; ô "Trạng thái" dưới đây chỉ là
> ảnh chụp, có thể lệch. Cập nhật ô trạng thái sau mỗi task đạt.

---

## 0. Nguyên tắc xếp thứ tự

1. **Ổn định trước, mở rộng sau.** Không chồng tính năng mới lên một cây đang có
   thay đổi chưa commit / chưa xanh test.
2. **Rủi ro tăng dần.** Việc nhỏ/an toàn (đóng gói, docs, refactor có test phủ)
   trước; việc nặng bảo mật (chạy scanner ngoài, đo từ xa) sau cùng — trùng với
   luật của ROADMAP.
3. **Tôn trọng phụ thuộc.** Một task chỉ mở khi mọi task nó phụ thuộc đã ĐẠT.
4. **Mỗi task = đúng một vòng orchestrator** và có **acceptance là lệnh chạy
   được**, không tiêu chí cảm tính.
5. **Mức pipeline tỷ lệ với rủi ro** (Direct / Compact / Full — xem ROADMAP §"Chọn
   mức pipeline"). Ghi sẵn mức đề xuất ở mỗi task.

---

## 1. Ảnh chụp hiện trạng (2026-07-17)

**Kiến trúc** (từ README §Under the hood):

| Thành phần | Trách nhiệm |
| --- | --- |
| `crates/sonar-core` | Entity, hợp đồng probe, scope rule, pivot graph, diễn giải kết quả |
| `crates/sonar-cli` | CLI + TUI trên core |
| `crates/sonar-os` | Trừu tượng hệ điều hành |
| `crates/sonar-tools` | Hợp đồng & vòng đời công cụ ngoài |
| `crates/sonar-report` | Báo cáo / export |
| `app/` | React + vỏ Tauri |

**Test baseline gần nhất ghi nhận** (docs/test, 2026-07-14): **89 test workspace
PASS**, `pnpm test` 19/19, `pnpm build` sạch. ⚠️ Con số này CÓ TRƯỚC khối thay
đổi chưa commit bên dưới — phải re-baseline (Task A1).

**Khối thay đổi CHƯA commit** (git diff, 18 file, +942/−519) — đây là việc dở
đang treo, KHÔNG phải rác:
- Redesign TUI `sonar-cli` (gõ thẳng lệnh CLI trong TUI, `Ctrl+P` mở workflow
  browser) — `tui.rs` +578/−, `view.rs`, `main.rs`.
- Đổi mô hình an toàn: "scope confirmation" → "bounded profiles + risk labels"
  (README, `docs/design/pages/{operations,tools}.md`, `sonar-core/interaction.rs`,
  `sonar-tools/{operations,remote}.rs`).
- App React gọn lại (`App.tsx` −, `styles.css` −, `lib.rs` −).
- File mới `.mcp.json` chưa track.

**Trạng thái ROADMAP** (đối chiếu commit thật):
- Phase 0 (nền xanh) — ✅ xong.
- Phase 1 (installer Windows) — **thực tế đã làm gần hết** qua commit gần đây
  (one-command installer, Scoop bucket, WinGet, self-update). Cần **xác minh
  đầu-cuối**, không phải xây mới.
- Phase 2 (bộ chạy công cụ ngoài) — Nmap/Nuclei có khung; mở rộng sang httpx,
  dnsx, subfinder, naabu, trippy/nexttrace **chưa làm** (📋).
- Phase 3 (đo từ xa thật + public port check) — mới dừng ở "tạo kế hoạch đo",
  **chưa thực thi** (📋).

---

## 2. Sơ đồ phụ thuộc (đọc từ trên xuống)

```text
EPIC A — Ổn định khối đang treo   (BẮT BUỘC làm trước tất cả)
   A1 re-baseline test  ─►  A2 chốt redesign TUI  ─►  A3 chốt mô hình profile/risk  ─►  A4 dọn .mcp.json + docs sync
                                          │
                                          ▼
EPIC B — Chốt & xác minh đóng gói (Phase 1)
   B1 verify installer đầu-cuối  ─►  B2 verify self-update path
                                          │
                                          ▼
EPIC C — Bộ chạy công cụ ngoài (Phase 2)   [Full pipeline — cửa bảo mật]
   C1 củng cố contract chung  ─►  C2 httpx  ─►  C3 dnsx  ─►  C4 subfinder
                                     └─► C5 naabu  ─► C6 trippy/nexttrace
                                          │
                                          ▼
EPIC D — Đo từ xa & public port (Phase 3)  [Full — rủi ro cao nhất, làm sau cùng]
   D1 Globalping thực thi thật  ─►  D2 public port check  ─►  D3 lịch sử/so sánh cho scanner+live

EPIC E — Xuyên suốt (làm xen kẽ khi chạm tới)
   E1 i18n VI/EN đủ  ·  E2 docs/test đồng bộ mỗi khi hành vi đổi  ·  E3 dọn nợ kỹ thuật có test phủ
```

**Luật cổng:** không mở EPIC B khi EPIC A chưa ĐẠT hết; không mở C khi B chưa
xong; D là cuối. E chạy kèm, không chặn.

---

## 3. Danh mục task (mỗi dòng = một đề orchestrator)

Ký hiệu trạng thái: 📋 chưa bắt đầu · 🚧 đang chạy · ✅ đạt · ⛔ chặn (chờ phụ thuộc).
Cột "Mức" = pipeline đề xuất. Cột "Worker" = model ưu tiên khởi đầu (đổi khi trượt).

### EPIC A — Ổn định khối đang treo

| ID | Đề (một câu) | Mức | Phụ thuộc | Trạng thái |
| --- | --- | --- | --- | --- |
| **A1** | Re-baseline: chạy toàn bộ test workspace + app trên cây HIỆN TẠI (có khối chưa commit), ghi lại con số thật, KHÔNG sửa gì ngoài việc làm cho nó xanh nếu đỏ | Compact | — | ✅ |
| **A2** | Chốt redesign TUI: rà `tui.rs/view.rs/main.rs`, đảm bảo gõ lệnh trực tiếp + `Ctrl+P` workflow browser hoạt động và có test phủ hành vi mới | Compact | A1 | ✅ |
| **A3** | Chốt mô hình an toàn mới "bounded profiles + risk labels": đảm bảo `sonar-core/interaction.rs` + `sonar-tools` nhất quán, không còn tàn dư "scope confirmation" mâu thuẫn, test khóa hành vi risk-label | Full | A1 | ✅ |
| **A4** | Dọn `.mcp.json` (track hay ignore — quyết định rõ) + đồng bộ README & docs/design với hành vi A2/A3, chạy `pnpm build` xác minh | Direct | A2, A3 | ✅ |

### EPIC B — Chốt & xác minh đóng gói (Phase 1)

| ID | Đề (một câu) | Mức | Phụ thuộc | Trạng thái |
| --- | --- | --- | --- | --- |
| **B1** | Xác minh installer đầu-cuối trên Windows: build portable bundle, chạy `install.ps1`, kiểm `sonar --version` + `sonar open ui` sau cài (ghi bằng chứng, không phát hành) | Full | A4 | ✅ |
| **B2** | Xác minh đường `sonar update` cho từng kênh cài (Scoop/WinGet/Cargo/portable): `sonar update --check` trả đúng trạng thái, không tự nâng khi chưa xác nhận | Compact | B1 | ✅ |

### EPIC C — Bộ chạy công cụ ngoài (Phase 2) — Full pipeline, cửa bảo mật bắt buộc

| ID | Đề (một câu) | Mức | Phụ thuộc | Trạng thái |
| --- | --- | --- | --- | --- |
| **C1** | Củng cố contract chung trong `sonar-tools`: dò-runtime → (tùy chọn) cài → preview lệnh → chạy có phạm vi → parse kết quả, đủ test để C2–C6 chỉ việc "điền công cụ" | Full | B1 | ✅ |
| **C2** | Nối **httpx** vào contract C1: dò, preview, run có scope, parse output; test tất định (không mạng) khóa parse | Full | C1 | ✅ |
| **C3** | Nối **dnsx** vào contract C1 (như C2) | Full | C1 | ⛔ |
| **C4** | Nối **subfinder** vào contract C1 (như C2) | Full | C1 | ⛔ |
| **C5** | Nối **naabu** vào contract C1 (như C2) | Full | C1 | ⛔ |
| **C6** | Nối **trippy / nexttrace** vào contract C1 (như C2) | Full | C1 | ⛔ |

### EPIC D — Đo từ xa & public port (Phase 3) — rủi ro cao nhất

| ID | Đề (một câu) | Mức | Phụ thuộc | Trạng thái |
| --- | --- | --- | --- | --- |
| **D1** | Globalping: biến "kế hoạch đo" thành **thực thi thật** — gọi API, nhận kết quả, diễn giải; token + vị trí + phạm vi là cổng bắt buộc | Full | C1 | ⛔ |
| **D2** | Public port check: từ "đã lên kế hoạch" → "dùng được" qua điểm quét từ xa có phạm vi | Full | D1 | ⛔ |
| **D3** | Lịch sử/so sánh mở rộng cho scanner + live probe (hiện chỉ probe thường có) | Compact | D1 | ⛔ |

### EPIC E — Xuyên suốt (chạy kèm, không chặn)

| ID | Đề (một câu) | Mức | Kích hoạt khi |
| --- | --- | --- | --- |
| **E1** | Quét sót i18n VI/EN, đảm bảo mọi chuỗi mới có cả hai ngôn ngữ | Direct | Bất kỳ task nào thêm chuỗi UI |
| **E2** | Đồng bộ `docs/test/*` và `docs/design/*` với hành vi mới | Direct | Bất kỳ task nào đổi hành vi người dùng thấy |
| **E3** | Trả nợ kỹ thuật (chỉ khi có test phủ để bảo vệ) | Compact | Khi worker/orchestrator phát hiện, ghi vào đây |

---

## 4. Khuôn acceptance cho từng loại task (worker phải ĐẠT hết)

Khi orchestrator sinh `docs/plan/<task>.md`, dùng đúng khuôn dưới đây làm
ACCEPTANCE CRITERIA (điều chỉnh theo phạm vi task), tất cả là lệnh chạy được:

**Task chạm Rust core/cli/tools:**
- `cargo test -p <crate liên quan>` → pass toàn bộ (ưu tiên `rtk cargo test ...`).
- `cargo test --workspace` → không giảm số test đang pass so với baseline (Task A1).
- `cargo clippy --workspace -- -D warnings` → 0 cảnh báo (nếu task hứa dọn nợ).
- Nếu đổi hành vi TUI (`crates/sonar-cli/src/tui*`): unit test không đủ để
  ĐẠT. Build `cargo build -p sonar-cli --release`, chạy
  `python scripts/tui-e2e/run.py` trên binary thật (script này lái TUI thật
  qua PTY thật, đọc màn hình đã dựng lại bằng `pyte`, không mock) → exit `0`.
  Nếu task thêm hành vi TUI mới ngoài 3 ca có sẵn (boot/palette/direct
  command), thêm ca mới vào `CASES` trong `scripts/tui-e2e/run.py` trước khi
  coi là ĐẠT — xem `scripts/tui-e2e/README.md`.

**Task chạm app/ (React/Tauri):**
- `pnpm test` (trong `app/`) → pass toàn bộ.
- `pnpm build` (trong `app/`) → build sạch.
- Nếu đổi hành vi UI: bổ sung/điều chỉnh ca trong `docs/test/TRANG-THAI-TEST.md`.
- Nếu đổi hành vi desktop thật (không chỉ layout/preview): unit test +
  `pnpm build` không đủ để ĐẠT. Build `pnpm tauri build` (trong `app/`), chạy
  `node scripts/gui-e2e/run.mjs` trên app thật (lái WebView2 thật qua CDP,
  không mock) → exit `0`. Nếu task thêm hành vi UI mới ngoài các ca có sẵn,
  thêm ca mới vào `CASES` trong `scripts/gui-e2e/run.mjs` trước khi coi là
  ĐẠT — xem `scripts/gui-e2e/README.md`.

**Task đóng gói / installer (B*):**
- Build ra đúng artifact nêu trong đề (portable zip / msi / cli exe).
- Lệnh nghiệm thu sau cài chạy đúng exit code (ví dụ `sonar --version` → 0).
- KHÔNG phát hành: dừng ở bằng chứng cục bộ, chờ user chốt.

**Task công cụ ngoài (C*) và đo từ xa (D*):**
- Test **tất định, không phụ thuộc mạng** khóa phần parse/scope (mạng thật để
  làn manual, như quy ước docs/test hiện tại).
- Cổng phạm vi bảo mật phải có test chứng minh "không chạy khi chưa khai báo scope".

---

## 5. Cách orchestrator dùng file này (vòng đời một task)

1. **Chọn task**: task 📋 đầu tiên mà mọi phụ thuộc đã ✅. Không nhảy cóc qua ⛔.
2. **Ra đề** (Bước 1 orchestrator): tạo branch `work/<id>-<slug>`, viết
   `docs/plan/<id>-<slug>.md` theo khuôn §4.
3. **Gọi worker** (Bước 2), **chấm** (Bước 3), tối đa 5 vòng.
4. **Đạt** → cập nhật ô Trạng thái task này thành ✅ trong file này (một dòng),
   mở khóa (⛔→📋) các task phụ thuộc, rồi Bước 4 (chờ user chốt merge/push).
5. **Không đạt sau 5 vòng** → để 🚧, tổng hợp, hỏi user. Không tự làm thay.

**Trạng thái nằm trong file, không nằm trong hội thoại.** Phiên chết giữa chừng
→ phiên mới đọc MASTERPLAN + các REPORT là tiếp tục được.

---

## 6. Nhật ký tiến độ (append, mới nhất trên cùng)

| Ngày | Task | Kết quả | Ghi chú |
| --- | --- | --- | --- |
| 2026-07-17 | v0.5.1 | RELEASE PREP | Không qua vai orchestrator — user yêu cầu tự tay test toàn bộ như người dùng thật rồi phát hành nếu ổn. Đã test: `cargo test --workspace` (205 passed/4 ignored, tăng đúng 3 test C2), `cargo clippy --workspace --all-targets -- -D warnings` (phát hiện 1 cảnh báo needless-borrow thật trong `summarize_httpx`, đã sửa 1 dòng), `pnpm test`/`pnpm build` sạch. Chạy CLI release thật + cài httpx thật + quét `scanme.nmap.org` (mục tiêu công khai được Nmap Project cho phép) — parser mới ra đúng số host/status/tech. Lặp lại y hệt qua TUI (PTY harness `scripts/tui-e2e/run.py` 3/3 + 1 phiên thủ công chạy httpx) và qua desktop app thật (`pnpm tauri build` + CDP harness `scripts/gui-e2e/run.mjs` 8/8 + 1 phiên thủ công chạy httpx từ tab Scanner). Không có vấn đề nào chặn phát hành. Merge `work/c2-httpx-parser` → `main`, bump version 0.1.3 → 0.5.1 (Cargo.toml/Cargo.lock/package.json/tauri.conf.json), cập nhật `release.md`. C2 chuyển ✅. |
| 2026-07-17 | C1 | ✅ PASS | 1 vòng orchestrator. Đóng lỗ hổng bảo mật thật: `scanner_invocation` (app-tauri) và `run_scanner_command` (sonar-cli) trước đó chạy scanner ngoài (nmap/nuclei/...) mà KHÔNG hề gọi scope check. Thêm `scanner_scope_gate` dùng chung trong `sonar-tools`, bắt buộc cả 2 call site đi qua trước khi build `CommandInvocation`. cargo test --workspace 202 passed/4 ignored, clippy 0 warning — verify độc lập bởi orchestrator. ⚠️ Worker tự `git commit` trái quy trình (đã báo user, user chọn giữ commit và merge — xem Feedback vòng 1 trong plan). C2-C6 mở khoá. |
| 2026-07-17 | B2 | ✅ PASS | 1 vòng orchestrator. Thêm unit test cho `update_channel` (5 kênh) + `confirm_update` (2 case) — trước đó chưa có test nào phủ. Xác nhận real `sonar update --check`/`sonar update` in "up to date", exit 0, không mutate (đúng lúc version workspace == release GitHub). cargo test --workspace 199 passed/4 ignored. Report vòng 1 đáng tin ngay, không cần vòng 2 (khác B1). EPIC B hoàn tất. |
| 2026-07-17 | B1 | ✅ PASS | 3 vòng orchestrator. Vòng 1 TRƯỢT (worker chẩn đoán sai, orchestrator tìm đúng gốc rễ: regex `\\s` escape sai trong install.ps1). Vòng 2 BLOCKED đúng cách (tìm thêm bug `$installRoot = $null` ghi đè tham số `-InstallRoot`, worker dừng thay vì cài liều vào path thật). Vòng 3 sửa đúng cả 3 dòng bug nhưng bằng chứng PATH before/after bị thiếu trên đĩa — orchestrator tự chạy lại toàn bộ acceptance criteria độc lập (không qua worker) để xác nhận ĐẠT thật. Không phát hành, không push. |
| 2026-07-17 | EPIC A | MERGED | `work/a4-cleanup-docs` merge --no-ff về `main` (2 commit: sản phẩm+docs, orchestrator scaffolding). Xác minh lại trên main: cargo test --workspace 185 passed/4 ignored, working tree sạch. Chưa push remote. |
| 2026-07-17 | A4 | ✅ PASS | 1 vòng orchestrator; README + docs/design synced, .mcp.json tracked, 30/30 vitest + 1802 modules + 185 workspace tests. |
| 2026-07-17 | A3 | ✅ PASS | 1 vòng orchestrator; InteractionRisk + bounded profiles implemented, scope_confirmed removed, 185 tests (+2). |
| 2026-07-17 | A2 | ✅ PASS | 1 vòng orchestrator; 52 sonar-cli tests, workspace 183 tests baseline maintained. |
| 2026-07-17 | A1 | ✅ PASS | 4 vòng orchestrator; 30/30 vitest, 1802 modules, 183 workspace tests. |
| 2026-07-17 | — | Tạo MASTERPLAN | Khởi tạo bản đồ; chưa chạy task nào. |
