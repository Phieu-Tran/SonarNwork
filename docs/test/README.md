# Luồng test SonarNwork — điểm vào (handoff)

Đây là **điểm vào** cho bất kỳ ai chạy luồng test SonarNwork — người thật hoặc
agent (Claude Code, Gemini CLI, **opencode**). Đọc trang này trước, rồi đi theo
đúng thứ tự bên dưới. Không cần đọc code sản phẩm để chạy được luồng.

## Bản đồ tài liệu (đọc theo thứ tự)

1. **`README.md`** (trang này) — luồng chạy, lệnh cụ thể, nơi ghi kết quả.
2. [`WORKFLOW.md`](WORKFLOW.md) — vai Test Runner, quy tắc, **xử lý drift**
   (re-baseline/retire khi product đổi), mẫu test handoff/launch 6 trục.
3. [`TRANG-THAI-TEST.md`](TRANG-THAI-TEST.md) — **bảng sống**: PASS/FAIL/ERROR
   từng ca, blocker, danh sách bug. **Đây là nơi ghi kết quả.**
4. [`../KICH-BAN-TEST-NGUOI-DUNG.md`](../KICH-BAN-TEST-NGUOI-DUNG.md) — chi tiết
   từng ca (mục A–H) + bảng bẫy `E1..E13`.
5. [`../../scripts/gui-e2e/README.md`](../../scripts/gui-e2e/README.md) — harness
   GUI tự động (lái app Tauri thật qua CDP).

## Quy tắc vàng (đọc trước khi chạy)

- **Đóng vai Test Runner, KHÔNG sửa code sản phẩm.** Chạy ca → so với kỳ vọng →
  ghi trạng thái. Nếu FAIL thật thì mô tả để chuyển vai dev (pipeline `.delivery/`),
  **không tự vá**.
- **KHÔNG commit / tag / publish** khi chưa được cho phép rõ ràng.
- **Chỉ quét mục tiêu bạn sở hữu / được phép** (`127.0.0.1`, host LAN của bạn).
  Không quét địa chỉ công cộng của người khác — kể cả khi app cho tick "được phép".
- **Không đụng `target/` của agent khác.** Mọi build Rust ở đây dùng
  `CARGO_TARGET_DIR` riêng (xem dưới). Frontend `pnpm` thì an toàn.
- Bám **spec** (`.delivery/<feature>/spec.md`), không bám code. Khi kỳ vọng lệch:
  theo mục "Xử lý test drift" trong [`WORKFLOW.md`](WORKFLOW.md) — phân biệt
  regression (giữ FAIL) vs kỳ vọng lỗi thời (re-baseline).

## Chuẩn bị môi trường

- Node ≥ 22 (harness GUI cần `fetch`/`WebSocket` toàn cục, 0 npm dep).
- `pnpm` cho frontend; Rust toolchain cho CLI/desktop.
- Target build riêng cho luồng test (tránh tranh khóa với agent khác):

  ```powershell
  $env:CARGO_TARGET_DIR = "C:\Temp\sonarnwork-test-target"
  ```

- Trước khi chạy lại làn GUI: **kill sạch** `sonarnwork-app` **và**
  `msedgewebview2` để không kẹt port 9222.

## Luồng chạy — theo thứ tự (nhẹ → nặng)

### Bước 1 — Làn tự động (nhanh, an toàn, không mạng bắt buộc)

Chạy trước để bắt regression rẻ. Ghi vào bảng **AUTO-01..05**.

```powershell
cd app; pnpm test          # vitest — logic frontend (AUTO-01)
cd app; pnpm build         # tsc + vite — build frontend (AUTO-02)
$env:CARGO_TARGET_DIR = "C:\Temp\sonarnwork-test-target"
cargo test --workspace     # core + scanner + tools + cli (AUTO-03..05)
```

### Bước 2 — Làn CLI (`sonarnwork`) — probe lõi qua dòng lệnh

Build một lần vào target riêng, rồi chạy các ca **CLI-\*** và **CLI-F\***.

```powershell
$env:CARGO_TARGET_DIR = "C:\Temp\sonarnwork-test-target"
cargo build -p sonar-cli --release
$CLI = "C:\Temp\sonarnwork-test-target\release\sonarnwork.exe"
& $CLI info
& $CLI ping 1.1.1.1 --count 3
& $CLI probe run web.http_probe example.com
# …danh sách ca đầy đủ trong TRANG-THAI-TEST.md (làn CLI) + KICH-BAN mục F
```

Ca CLI **tất định (không mạng)** đã được khóa trong `crates/sonar-cli/tests/cli.rs`
(chạy bằng `cargo test -p sonar-cli`). Ca CLI **có mạng** (ping/http/dns thật) giữ
ở làn manual này.

### Bước 3 — Làn UI-preview (Vite browser)

Test bố cục, copy/dấu tiếng Việt, đổi ngôn ngữ/theme, empty/disabled state. Ghi
vào **UIP-\***. **Không** test được scan/probe thật (không có backend Tauri).

```powershell
cd app; pnpm dev           # cổng 1730 — lái bằng Playwright MCP
```

### Bước 4 — Làn UI-desktop (Tauri thật, tự động qua CDP)

Test scan thật, detect tool, verdict live, scope. Ghi vào **UID-\***, **DIR-\***,
**SCOPE-\***. Đây là làn duy nhất chạy được luồng chủ động thật.

```powershell
cd app; pnpm tauri build   # build app release (harness cần bản đã build)
node scripts/gui-e2e/run.mjs
```

- Exit 0 = tất cả pass, 1 = có ca fail, 2 = fatal (app chưa build / CDP chưa sẵn).
- Ảnh bằng chứng: `scripts/gui-e2e/screenshots/`.
- Thêm ca mới: xem [`../../scripts/gui-e2e/README.md`](../../scripts/gui-e2e/README.md).

## Ghi kết quả

Ghi thẳng vào [`TRANG-THAI-TEST.md`](TRANG-THAI-TEST.md), **tại chỗ** (đổi ô Trạng
thái, không xoá lịch sử FAIL). Trạng thái:
`✅ PASS · ❌ FAIL · ⚠️ ERROR · ⏳ PENDING · 🟡 PARTIAL`. Mỗi dòng:
**ID · Làn · Ca · Trạng thái · Bằng chứng · Ngày**. Giữ mã bẫy `E#` xuyên suốt để
nối UI ↔ CLI ↔ code.

## Blocker / bug đang treo (xem chi tiết ở TRANG-THAI-TEST.md)

Trước khi báo bug mới, kiểm bảng "Vướng khi test" và "Tổng hợp nhanh" trong
[`TRANG-THAI-TEST.md`](TRANG-THAI-TEST.md) — một số ca **đã biết** đang chặn:

- **E13** — GUI `run_probe` vẫn dùng `AppCore::default()` → mọi probe có target từ
  GUI bị `scope denied`. Chặn **UID-01** (E3 verdict) và **SCOPE-02**. CLI không
  dính (dùng `for_explicit_target`).
- **DIR-02** — 10 probe có label `"local → …"` nhưng màu **đỏ (outbound)**, lệch
  spec (KICH-BAN gom local+outbound = cam).
- **E6** — còn vài chuỗi rớt dấu / chưa dịch. **E11** — app không detect nuclei
  ngoài PATH.

Nếu chạy lại và các blocker này đã được sửa ở code → **re-baseline** theo quy trình
trong [`WORKFLOW.md`](WORKFLOW.md) (đối chiếu spec trước, đừng vội đổi cả code lẫn test).
