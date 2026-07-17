# A2 — Chốt redesign TUI

## Trạng thái

- Task: `A2`
- Pipeline: Compact
- Branch: `work/a2-redesign-tui`
- Vòng hiện tại: 1
- Engine: `claude` / alias `api-combo`
- Trạng thái: PENDING — chờ dispatch vòng 1

## Mục tiêu

Hoàn thiện design TUI mới của sonar-cli: xác nhận gõ lệnh trực tiếp trong terminal + Ctrl+P mở workflow browser hoạt động đúng, không có hành vi sai hay kết xuất bỏ sót; tất cả thay đổi TUI phải có test phủ.

## Phạm vi

### Được sửa trong vòng 1

- `crates/sonar-cli/src/tui.rs`: vòng lặp chính, xử lý input, dispatch command
- `crates/sonar-cli/src/tui/view.rs`: render TUI components, output format
- `crates/sonar-cli/src/main.rs`: TUI entrypoint, dispatcher CLI/TUI mode
- Test trong `crates/sonar-cli/tests/cli.rs`: thêm/cập nhật ca test cho hành vi TUI mới
- README.md, docs/design/pages nếu cần ghi nhận hành vi TUI

### Không được làm

- Sửa logic core probe/scanner trong `sonar-core`
- Thêm công cụ ngoài mới (đó là C-series)
- Thay đổi data model entity/catalog
- Commit hay push (chỉ stage file tài liệu)

## Trình tự thực hiện

1. Đọc `crates/sonar-cli/src/tui.rs` toàn bộ để hiểu design hiện tại: entry point, input dispatcher, workflow browser (Ctrl+P), lệnh nhập trực tiếp
2. Kiểm tra `tui/view.rs` và `main.rs` xác nhận flow hoàn chỉnh
3. Chạy `cargo test -p sonar-cli` để xem test hiện tại phủ gì
4. Nếu test không đủ hoặc thiếu hành vi, viết thêm test + sửa code để pass
5. Chạy `cargo test --workspace` xác nhận không giảm số test so với A1 baseline (183)
6. Cập nhật docs hoặc README nếu TUI behavior đã thay đổi

## ACCEPTANCE CRITERIA

Chạy từ PowerShell, thứ tự:

1. `cargo test -p sonar-cli`
   - Exit code `0`.
   - Toàn bộ test sonar-cli pass; report ghi đúng số test thực tế (hiện tại baseline từ A1).

2. `cargo test --workspace`
   - Exit code `0`.
   - Mọi test pass; số test ≥ 183 (không giảm so với A1).

3. `cargo build -p sonar-cli --release`
   - Exit code `0`.
   - Release CLI build thành công, không có warning nếu có thể.

4. Đọc lại `crates/sonar-cli/src/tui.rs`, `view.rs`, `main.rs` và xác nhận:
   - Gõ lệnh trực tiếp trong TUI → được dispatch đúng (ví dụ `ping 1.1.1.1` gọi probe)
   - `Ctrl+P` hoặc keybind workflow browser → mở panel chọn workflow
   - Workflow được chọn → quay lại thực thi có test lock
   - Input validation có test để chứng minh không chạy lệnh sai định dạng

5. Nếu thay đổi hành vi người dùng thấy: cập nhật `docs/test/TRANG-THAI-TEST.md` hoặc README.md để ghi hành vi mới

6. `git diff --exit-code -- crates app` → chỉ chứa file được sửa (tui.rs, view.rs, main.rs, test); không có thay đổi sản phẩm vô ý (cây A1 có diff sẵn được chấp nhận)

## Feedback vòng 1

_Để trống._

## Feedback vòng 2

_Để trống._

## Feedback vòng 3

_Để trống._

## Feedback vòng 4

_Để trống._

## Feedback vòng 5

_Để trống._
