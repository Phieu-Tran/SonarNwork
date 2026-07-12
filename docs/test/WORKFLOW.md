# Workflow luồng test người dùng

Quy trình chuẩn để **đóng vai người dùng** test SonarNwork, tách rõ **2 làn**:
**CLI** và **UI**. Ai cũng đóng được vai này — người thật, Claude Code, Gemini
CLI, hay opencode.

## Vai: Người chạy test (Test Runner)

- **Đầu vào**: các ca test trong [`../KICH-BAN-TEST-NGUOI-DUNG.md`](../KICH-BAN-TEST-NGUOI-DUNG.md).
- **Việc**: chạy từng ca → so kết quả thật với kỳ vọng → **ghi trạng thái** vào
  [`TRANG-THAI-TEST.md`](TRANG-THAI-TEST.md).
- **Không** sửa code sản phẩm khi đang ở vai test; chỉ ghi nhận. Việc sửa là vai
  khác (dev), theo pipeline `.delivery/`.
- **Không** commit/tag/publish khi chưa được phép.

## Hai làn test

### Làn CLI (`sonarnwork`) — nhẹ, an toàn, không cần GUI

Kiểm lõi `sonar-core` qua CLI của sản phẩm. **Không đụng `target/` của agent
khác** nhờ build vào target riêng:

```bash
# build một lần vào target riêng (không trùng codex)
CARGO_TARGET_DIR="<thư-mục-tạm>/cli-target" cargo build -p sonar-cli
# binary sinh ra tên: sonarnwork(.exe)
CLI="<thư-mục-tạm>/cli-target/debug/sonarnwork.exe"
"$CLI" info
"$CLI" ping 1.1.1.1 --count 3
"$CLI" probe run web.http_probe example.com
```

Phù hợp cho: các ca **F** (probe thường) và bất cứ gì kiểm được bằng dòng lệnh.
Ưu điểm: nhanh, không mở cửa sổ, chạy song song với codex thoải mái.

### Làn UI — 2 mức

1. **UI preview (Vite)** — `cd app && pnpm dev` (cổng 1730), lái bằng Playwright
   MCP. **Không** đụng `target/` Rust. Test được: bố cục, copy/dấu tiếng Việt,
   chọn workflow/probe, đổi ngôn ngữ/theme, empty/disabled state.
   **Không** test được: chạy probe/scan thật, install, terminal (không có backend
   Tauri → tab scanner trống).

2. **UI desktop thật (Tauri)** — `cd app && pnpm tauri dev` hoặc chạy installer.
   Test được **tất cả**: scan thật, Install/Update, tải Nuclei, mở CLI/terminal,
   verdict live. **Cần cửa sổ native** → do người thật hoặc agent có khả năng lái
   GUI thực hiện. ⚠️ Build Rust → **đợi codex dừng** hoặc dùng `CARGO_TARGET_DIR`
   riêng để khỏi tranh khóa.

## Quy trình mỗi ca test

1. Chọn ca (mã như `F2`, `B4`, `E10`…).
2. Chạy theo đúng bước trong kịch bản.
3. So sánh: **input → thực tế → kỳ vọng**.
4. Ghi vào `TRANG-THAI-TEST.md`:
   - **PASS**: đúng kỳ vọng.
   - **FAIL**: sai kỳ vọng → ghi rõ *thấy gì vs mong gì*, gắn mã bẫy `E#` nếu có.
   - **ERROR**: không chạy được ca (thiếu môi trường, lệnh lỗi hạ tầng).
   - **PENDING**: chưa chạy (vd cần bản desktop mà chưa có).
5. Nếu là **FAIL/ERROR thật** → chuyển cho vai dev (mô tả để sửa theo `.delivery/`).

## Nguyên tắc cập nhật trạng thái

- Mỗi dòng trong bảng có: **ID · Làn · Ca · Trạng thái · Bằng chứng · Ngày**.
- Cập nhật **tại chỗ** (đổi ô Trạng thái), không xoá lịch sử FAIL — nếu đã sửa và
  chạy lại thì đổi thành `PASS (đã sửa)` kèm ngày.
- Giữ mã bẫy `E#` xuyên suốt để nối UI ↔ CLI ↔ code.

## Xử lý test drift (khi product đổi)

Test bám **spec** (`.delivery/<feature>/spec.md`), không bám code, cũng không bám
chính nó. Khi tính năng đổi, sửa **spec trước** → test re-derive kỳ vọng. Không
bao giờ vá test để chạy theo code.

### Khi một ca lệch kỳ vọng — phân biệt 2 loại

| Loại | Nghĩa | Xử lý |
| --- | --- | --- |
| **Regression** | product hỏng so với ý định | giữ FAIL, gắn mã lỗi, chuyển vai dev |
| **Kỳ vọng lỗi thời** | product cố ý đổi, test còn ôm cấu trúc cũ | **re-baseline**: cập nhật cột kỳ vọng, không đụng code |

Phân biệt bằng **spec/ý định**, không đoán: spec nói hành vi mới là đúng → re-baseline;
spec vẫn yêu cầu hành vi cũ → regression.

### Ba kiểu đổi tính năng

- **Thêm**: thêm ca mới (ID mới) + `Verifies` + (nếu kiểm được bằng máy) test tự động.
- **Thắt/sửa**: giữ ID, **đổi kỳ vọng**, đánh `PASS (đã sửa) — vì spec X, ngày…`,
  giữ lịch sử. Nếu đã có test tự động khóa hành vi cũ → cập nhật assertion của nó.
- **Bỏ**: **retire** ca test (đánh "superseded") **và xóa test tự động** khóa nó.
  Đừng để test cũ FAIL hoài cho thứ đã cố ý bỏ → người ta quen bỏ qua đèn đỏ.

### Quy trình re-baseline

1. Ca lệch kỳ vọng → dừng, **đừng vội sửa cả code lẫn test**.
2. Đối chiếu spec: hành vi mới có phải ý định không?
3. Có → sửa cột **Trạng thái + Bằng chứng**, ghi ngày + lý do; tra cột `Verifies`
   để tìm hết các ca liên quan cùng tính năng và xem lại một thể.
4. Không → regression thật, giữ FAIL.
5. Nếu bug đã fix và **đã có test tự động khóa** (như E2/E10) → không thêm test
   trùng; chỉ ghi nhận lock đó trong bảng.

**Ví dụ thật (2026-07-11):** E10 (`domain:port`) và E2 (Nuclei URL) từng là FAIL;
codex sửa product + thêm test khóa. Đúng quy trình: phát hiện product đổi →
re-verify → re-baseline sang `PASS (đã sửa)` → **không** thêm test `#[ignore]`
mâu thuẫn. Đó là drift được xử lý đúng.

## Mẫu test cho tính năng handoff/launch

Áp dụng cho **mọi nút "mở / khởi chạy thứ bên ngoài"**: Mở CLI, Mở terminal
(PS/CMD), Mở trang installer (nmap.org), mở browser, và các nút tương tự sau này.
Loại này luôn có cùng bộ trạng-thái-lỗi, nên test theo **6 trục**:

1. **Kích hoạt** — bấm có mở không? Mở đúng **một** lần (không đẻ cửa sổ rác)?
2. **Đúng đích** — mở đúng thứ: đúng shell (PS/CMD), đúng URL, đúng chương trình
   (`sonar-cli` hay lệnh thô?).
3. **Đúng nội dung** — lệnh/URL bên trong **khớp preview**; không rơi/thừa tham số;
   ký tự đặc biệt trong target không làm hỏng và không escape sai.
4. **Đúng trạng thái chạy** — theo **spec**: **tự chạy** hay **dán-chờ**? cửa sổ
   **giữ** hay tự đóng? (đây là câu hỏi spec — phải khớp ý định, không đoán).
5. **Lỗi & biên** — nền không hỗ trợ, shell/URL sai, scope bị từ chối, target rỗng
   → **báo lỗi rõ ràng**, không im lặng, không crash.
6. **An toàn** — không command/URL injection; scope/quyền được thực thi **trước khi**
   mở (vd installer chỉ nhận HTTPS; override cần `ExternalTool` scope).

**Cách dùng:** với mỗi tính năng handoff, copy 6 trục thành 6 ca, điền ĐẠT/LỖI cụ
thể. Ví dụ đã điền sẵn: mục **D** (Mở CLI) trong kịch bản, có bảng D4 cho trục 3–6.
Các tính năng cùng loại phải test y vậy: **Mở installer Nmap** (B2), **Mở terminal
scanner** (Nmap/Nuclei), và bất kỳ nút "mở ra ngoài" nào thêm về sau.
