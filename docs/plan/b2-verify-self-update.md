# B2 — Xác minh đường `sonar update`

## Trạng thái

- Task: `B2`
- Pipeline: Compact
- Branch: `work/b2-verify-self-update`
- Vòng hiện tại: 1 (ĐẠT)
- Engine: `claude` / alias `api-combo`
- Trạng thái: ✅ PASS — xác minh lại độc lập bởi orchestrator: `cargo test -p
  sonar-cli` 97 passed, `cargo test --workspace` 199 passed/4 ignored (≥185
  baseline), `sonar update --check` và `sonar update` (thật, release binary)
  đều in "up to date", exit 0, không mutate. Diff chỉ +70 dòng test trong
  `update.rs`. Chờ user xác nhận Bước 4.

## Mục tiêu

Xác minh lệnh `sonar update` (`crates/sonar-cli/src/update.rs`) hoạt động đúng
cho từng kênh cài (Scoop/WinGet/Cargo/portable) và **không tự nâng cấp khi
chưa có xác nhận**:

1. `update_channel(&Path)` (dòng 150-187) là hàm thuần (nhận `&Path`, trả
   `UpdateChannel`, không I/O) nhưng **chưa có test nào**. Thêm unit test phủ
   đủ các nhánh: Scoop, WinGet, Cargo, WindowsPortable, và
   `target/debug`|`target/release` → `Unsupported`.
2. `confirm_update(version, confirmed)` (dòng 127-147) cũng thuần I/O-nhẹ:
   nếu `confirmed = true` → `Ok` ngay, không đọc stdin. Nếu `confirmed = false`
   và stdin không phải TTY (đúng môi trường `cargo test` mặc định) →
   `Err`, KHÔNG tự tiến hành cập nhật. Đây chính là cơ chế "không tự nâng khi
   chưa xác nhận" — cần test khóa hành vi này.
3. Chạy thật `sonar update --check` (chỉ đọc, gọi GitHub API thật, KHÔNG mutate
   gì) để xác nhận output đúng trạng thái hiện tại.
4. Chạy thật `sonar update` (không `--yes`, không `--check`) trong điều kiện
   hiện tại (version workspace == version release mới nhất trên GitHub, xem
   dưới) để xác nhận nó tự nhận biết "đã mới nhất" và dừng AN TOÀN, không hỏi
   xác nhận, không đụng channel/mutate.

## CẢNH BÁO RỦI RO HỆ THỐNG — đọc kỹ trước khi chạy

`sonar update` (không có `--check`) trên nhánh KHÔNG phải "đã mới nhất" sẽ:
- Gọi `scoop update` / `winget upgrade` / `cargo install --git ...` thật (kênh
  Scoop/Winget/Cargo), HOẶC
- Tải và tự chạy lại `install.ps1` thật (kênh portable) — cùng rủi ro ghi đè
  User PATH thật đã cảnh báo ở B1, cộng thêm tự thoát tiến trình hiện tại để
  script ghi đè file đang chạy.

**Hiện tại `Cargo.toml` version = `0.1.3`, trùng với release GitHub mới nhất
`v0.1.3`** (worker PHẢI tự `curl -s https://api.github.com/repos/Phieu-Tran/SonarNwork/releases/latest`
để xác nhận lại con số này chưa đổi trước khi chạy bất kỳ lệnh thật nào — nếu
đã có release mới hơn được publish từ lúc viết plan này, DỪNG NGAY, không chạy
`sonar update` thật dưới bất kỳ hình thức nào, chỉ báo cáo lại cho orchestrator).
Vì `ordering = Equal` khi hai version bằng nhau, `run()` in "up to date" và
`return Ok(())` NGAY (dòng 50-53 `update.rs`), TRƯỚC khi chạm tới
`confirm_update` hay bất kỳ channel nào — do đó chạy `sonar update` thật (kể
cả không `--check`, không `--yes`) trong đúng điều kiện này là AN TOÀN 100%,
không mutate gì. **Nếu điều kiện version-bằng-nhau không còn đúng khi worker
chạy, TUYỆT ĐỐI không chạy `sonar update` thật (chỉ `--check` là an toàn ở mọi
trạng thái) — dừng và báo cáo.**

## Phạm vi

### Được sửa trong vòng 1

- `crates/sonar-cli/src/update.rs`: CHỈ thêm test vào module `#[cfg(test)] mod tests`
  đã có sẵn (dòng ~398-446) — không sửa logic sản phẩm (`run`, `update_channel`,
  `confirm_update`, `latest_release`, …). Nếu phát hiện bug thật khi viết test
  (giống bug B1), DỪNG lại, báo cáo cụ thể, không tự vá — quay lại orchestrator
  quyết định mở khoá thêm.
- Không sửa file nào khác.

### Không được làm

- Không chạy `sonar update` thật (không `--check`) nếu chưa tự xác nhận
  version workspace == version release GitHub mới nhất (xem cảnh báo trên).
- Không chạy `scoop`, `winget`, `cargo install --git`, hay bất kỳ lệnh nào
  thật sự cài/nâng cấp package.
- Không push, không commit, không tạo release.
- Không sửa `scripts/install.ps1` (đã xong ở B1).

## Trình tự thực hiện

1. `curl -s https://api.github.com/repos/Phieu-Tran/SonarNwork/releases/latest`
   → xác nhận `tag_name` vẫn là `v0.1.3` (khớp `Cargo.toml`). Ghi kết quả vào
   report dù khớp hay không.
2. Đọc `crates/sonar-cli/src/update.rs` dòng 1-200 để hiểu rõ `UpdateChannel`,
   `update_channel`, `confirm_update`, `run`.
3. Thêm unit test cho `update_channel`: dùng `Path::new("...")` giả lập từng
   dạng đường dẫn thật của từng kênh (xem log các pattern ở dòng 156-181),
   verify trả đúng variant. Phủ tối thiểu: Scoop, Winget, Cargo,
   WindowsPortable (một path bất kỳ không khớp 3 kênh trên, không nằm trong
   `target/debug`|`target/release`), và `target/release` → `Unsupported`.
4. Thêm unit test cho `confirm_update`:
   - `confirm_update("v9.9.9", true)` → phải `Ok(())`, không được chạm stdin.
   - `confirm_update("v9.9.9", false)` → trong môi trường `cargo test` (stdin
     không phải TTY) phải trả `Err`, chứng minh không tự tiến hành khi chưa
     xác nhận.
5. `cargo test -p sonar-cli` → toàn bộ pass, bao gồm test mới.
6. (Chỉ nếu bước 1 xác nhận version vẫn khớp) Chạy thật:
   - `cargo run -p sonar-cli --release -- update --check` → ghi output + exit code.
   - `cargo run -p sonar-cli --release -- update` (không `--yes`) → ghi output
     + exit code, xác nhận in "up to date" và không hỏi xác nhận gì.
7. `cargo test --workspace` → không giảm số test so với baseline B1 (185 passed).
8. Viết `docs/plan/REPORT-b2-verify-self-update.md` — **dùng tool ghi file
   thật** (Write/Edit), không chỉ trả lời trong hội thoại (bài học từ B1 vòng
   3). Ghi rõ: kết quả bước 1 (version check), danh sách test mới thêm, output
   thật của bước 6 nếu có chạy, kết quả `cargo test -p sonar-cli` và
   `cargo test --workspace`.

## ACCEPTANCE CRITERIA

Chạy từ PowerShell/bash, thứ tự:

1. `curl -s https://api.github.com/repos/Phieu-Tran/SonarNwork/releases/latest`
   → ghi lại `tag_name` thực tế vào report (dù bằng hay khác `v0.1.3`).

2. `cargo test -p sonar-cli update::tests`
   - Exit code `0`.
   - Bao gồm ít nhất các test mới cho `update_channel` (≥4 case: Scoop, Winget,
     Cargo, Unsupported) và `confirm_update` (2 case: confirmed=true,
     confirmed=false-non-tty).

3. `cargo test -p sonar-cli`
   - Exit code `0`, toàn bộ pass.

4. `cargo test --workspace`
   - Exit code `0`.
   - Số test ≥ 185 (baseline B1), tăng đúng bằng số test mới thêm ở bước 2.

5. NẾU và CHỈ NẾU bước 1 xác nhận version khớp (`v0.1.3` == `v0.1.3`):
   - `cargo run -p sonar-cli --release -- update --check` → exit `0`, output
     chứa "up to date" (hoặc thông báo tương đương xác nhận không có bản mới).
   - `cargo run -p sonar-cli --release -- update` (không cờ) → exit `0`,
     output chứa "up to date", KHÔNG có dòng hỏi xác nhận "Install SonarNwork...".
   - Nếu version LỆCH nhau: bỏ qua tiêu chí này, ghi rõ lý do trong report,
     KHÔNG chạy các lệnh trên.

6. `git status --short` → chỉ `crates/sonar-cli/src/update.rs` (modified,
   thêm test) + `docs/plan/REPORT-b2-verify-self-update.md`; không có file
   sản phẩm nào khác bị đổi.

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
