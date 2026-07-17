# C1 — Củng cố contract chung cho bộ chạy công cụ ngoài (đóng lỗ hổng scope)

## Trạng thái

- Task: `C1`
- Pipeline: Full (cửa bảo mật bắt buộc)
- Branch: `work/c1-tool-contract`
- Vòng hiện tại: 1 (ĐẠT kỹ thuật, có vi phạm quy trình)
- Engine: `claude` / alias `api-combo`
- Trạng thái: ✅ PASS về mặt kỹ thuật — xác minh độc lập: `cargo build --workspace`
  sạch, `cargo test --workspace` 202 passed/4 ignored (baseline 199 + 3 test
  mới), `cargo clippy --workspace --all-targets -- -D warnings` 0 cảnh báo.
  Cả 2 call site (`scanner_invocation` app-tauri, `run_scanner_command`
  sonar-cli) đã xác nhận đi qua `scanner_scope_gate` duy nhất, không còn
  đường nào build được `CommandInvocation` runnable mà bỏ qua scope check.
  ⚠️ NHƯNG worker đã tự `git commit` (`9c7ad58`) — VI PHẠM chỉ dẫn "Không
  commit" trong plan. Đã báo cho user quyết định trước khi merge.

## Bối cảnh — LỖ HỔNG BẢO MẬT THẬT ĐÃ XÁC ĐỊNH

Orchestrator đã tự điều tra trước khi ra đề (không cần worker dò lại từ đầu).
Repo có model an toàn "bounded profiles + risk labels" (EPIC A) và cơ chế
`ScopeGuard`/`ActionClass` (`crates/sonar-core/src/scope.rs`) + `AppCore::ensure_allowed_for_target`
(`crates/sonar-core/src/app.rs:232-239`). **NHƯNG cả hai đường chạy scanner
ngoài trực tiếp (nmap/nuclei/httpx/dnsx/subfinder/naabu/trippy/nexttrace) đều
hoàn toàn không gọi cơ chế này**, khác với `run_probe_live` (đã đúng, dùng làm
mẫu tham chiếu):

1. **`app/src-tauri/src/lib.rs::scanner_invocation`** (dòng 127-152) — được
   `run_scanner_live` (dòng 474-493) gọi để chạy tiến trình thật trong app
   desktop. Build `CommandInvocation` thẳng từ `target` thô, chỉ kiểm tra
   runtime có sẵn (`runtime.available`), KHÔNG có bước `AppCore::for_explicit_target`
   + `ensure_allowed_for_target` nào. So sánh với `run_probe_live` (dòng
   439-460) dùng đúng `app_core_for_target(&target)` (dòng 462-469, hàm sẵn
   có, tái dùng được) rồi mới build invocation — MẪU CẦN COPY.
2. **`crates/sonar-cli/src/main.rs::run_scanner_command`** (dòng 1676-1706+)
   — lệnh `sonar scanner run <tool> <target>`. Build `CommandInvocation` từ
   `target: String` thô rồi `std::process::Command::new(...).output()` NGAY,
   không có `AppCore`/scope check nào ở bất kỳ đâu trong hàm.

Kết quả: **hôm nay, ai gõ `sonar scanner run nmap <bất_kỳ_target_nào>` hoặc bấm
chạy scanner trong app desktop đều KHÔNG bị chặn bởi scope**, bất kể target đó
có nằm trong phạm vi đã khai báo hay không. Đây chính là lỗ hổng MASTERPLAN §4
yêu cầu C1 phải đóng ("Cổng phạm vi bảo mật phải có test chứng minh 'không
chạy khi chưa khai báo scope'").

`ExternalScannerKind::action_class()` (`crates/sonar-core/src/scanner.rs:77-84`)
đã có sẵn, map đúng mỗi tool sang `ActionClass` (nmap/httpx/trippy/nexttrace =
`ActiveProbe`; nuclei/naabu/dnsx = `IntrusiveScan`; subfinder = `PassiveLookup`).
Không cần tạo mới — chỉ cần THỰC SỰ GỌI nó ở đúng chỗ.

## Mục tiêu

1. Thêm **một hàm dùng chung duy nhất** trong `sonar-tools` (crate cả
   `app/src-tauri` lẫn `sonar-cli` đều phụ thuộc, và `sonar-tools` đã phụ
   thuộc sẵn `sonar-core`) làm cổng bắt buộc: nhận target + action class +
   invocation đã build sẵn, gọi `AppCore::ensure_allowed_for_target`, chỉ trả
   về `CommandInvocation` runnable nếu scope cho phép; trả lỗi rõ ràng nếu
   không. Đặt tên hàm/kiểu tuỳ worker, miễn giữ đúng tính chất: **không có
   cách nào lấy được `CommandInvocation` runnable của một scanner mà bỏ qua
   được bước gọi hàm này** trong hai call site dưới đây.
2. Sửa `scanner_invocation` (app-tauri) và `run_scanner_command` (sonar-cli)
   để đi qua cổng mới này trước khi build/trả về invocation — không tự ý
   build invocation runnable rồi bỏ qua cổng.
3. Test tất định (không mạng, không cần binary ngoài cài sẵn) chứng minh:
   target ngoài phạm vi khai báo → bị chặn TRƯỚC khi có invocation runnable;
   target trong phạm vi → vẫn hoạt động y như cũ (không phá hành vi hiện tại
   của nmap/nuclei).

## Phạm vi

### Được sửa trong vòng 1

- `crates/sonar-tools/src/lib.rs` (hoặc file mới cùng crate, tự quyết định,
  khai báo `mod` đúng chuẩn Rust): hàm/kiểu cổng scope mới + test.
- `app/src-tauri/src/lib.rs`: sửa `scanner_invocation` (dòng 127-152) để gọi
  cổng mới, dùng lại `app_core_for_target` đã có sẵn (dòng 462-469) — KHÔNG
  viết lại logic resolve `AppCore` từ đầu.
- `crates/sonar-cli/src/main.rs`: sửa `run_scanner_command` (dòng 1676+) để
  gọi cổng mới. Trước khi sửa, đọc cách các lệnh khác trong file này đã dựng
  `AppCore` cho một target dạng chuỗi thô (ví dụ dòng ~987 dùng
  `AppCore::default()` cho lệnh không gắn target cụ thể — KHÔNG dùng mẫu đó
  cho scanner vì scanner luôn có target thật; dùng `AppCore::for_explicit_target`
  qua `ProbeTarget::Input(target.clone())`, đúng kiểu `app_core_for_target`
  bên app-tauri xử lý biến thể `ProbeTarget::Input`).
- Thêm test (unit hoặc integration tùy vị trí) ở cả 3 crate bị đụng: chứng
  minh cổng chặn đúng, không phá test cũ.

### Không được làm

- KHÔNG viết logic riêng cho httpx/dnsx/subfinder/naabu/trippy/nexttrace —
  đó là việc của C2-C6. C1 chỉ đóng cổng chung, áp dụng như nhau cho MỌI
  scanner đã có (`ExternalScannerKind` hiện tại).
- KHÔNG đổi `ExternalScannerKind::action_class()` hay bảng map risk hiện có
  trong `sonar-core/src/scanner.rs` — chỉ tiêu thụ nó.
- KHÔNG chạy binary ngoài thật (nmap/nuclei/...) trong bất kỳ test nào — test
  phải tất định, không phụ thuộc mạng hay binary cài sẵn trên máy CI/worker
  (đúng khuôn MASTERPLAN §4 cho task C*/D*).
- KHÔNG sửa UI React (`app/src/`), KHÔNG sửa `operations.rs`/`remote.rs`
  (không liên quan — đã xác nhận qua nghiên cứu trước khi ra đề).
- KHÔNG sửa `scanner_cli_invocation` (app-tauri, dòng 154-185, dùng cho
  "mở terminal" preview, không tự thực thi) — ngoài phạm vi vòng này, để dành
  nếu orchestrator quyết định mở rộng ở vòng sau.
- Không push, không commit.

## Trình tự thực hiện

1. Đọc `crates/sonar-core/src/scope.rs` (toàn bộ, ngắn) hiểu `ActionClass`,
   `ScopeGuard::ensure_allowed`.
2. Đọc `crates/sonar-core/src/app.rs` dòng 150-240: `AppCore::for_explicit_target`,
   `AppCore::default`, `AppCore::ensure_allowed_for_target`.
3. Đọc `crates/sonar-core/src/scanner.rs` dòng 70-90: `ExternalScannerKind::action_class`.
4. Đọc `app/src-tauri/src/lib.rs` dòng 120-500: `scanner_invocation`,
   `scanner_cli_invocation`, `run_probe_live`, `app_core_for_target`,
   `run_scanner_live`, `invocation_with_override` (dòng ~690-710, mẫu gọi
   `ensure_allowed_for_target` đã đúng — copy đúng tinh thần, không copy
   nguyên văn vì ngữ cảnh khác).
5. Đọc `crates/sonar-cli/src/main.rs` dòng 1670-1720: `run_scanner_command`.
6. Thiết kế + implement hàm cổng trong `sonar-tools` theo mục tiêu #1.
7. Sửa `scanner_invocation` (app-tauri) theo mục tiêu #2. Chạy
   `cargo test -p sonarnwork-app` (tên package thật của `app/src-tauri`, xem
   `app/src-tauri/Cargo.toml:2`) xác nhận test cũ (dòng 1236-1280,
   `custom_command_cannot_replace_the_scoped_*`) vẫn pass, thêm test mới cho
   `scanner_invocation`/cổng mới.
8. Sửa `run_scanner_command` (sonar-cli) theo mục tiêu #2. Có thể cần tách
   một hàm con "build + authorize invocation" ra khỏi hàm hiện tại để test
   được mà không phải spawn tiến trình thật (hiện `run_scanner_command` làm
   cả hai việc trong 1 hàm) — tách theo đúng tinh thần `scanner_invocation`
   (app-tauri) đã tách "build invocation" khỏi "spawn" từ trước.
9. `cargo test --workspace` → không giảm test so với baseline B2 (199 passed,
   4 ignored), tăng đúng số test mới thêm.
10. `cargo clippy --workspace --all-targets -- -D warnings` → 0 cảnh báo.
11. Viết `docs/plan/REPORT-c1-tool-contract.md` bằng tool ghi file thật
    (Write/Edit) — bài học từ B1 vòng 3, không chỉ trả lời trong hội thoại.
    Liệt kê rõ: hàm cổng mới tên gì, ở đâu; 2 call site đã sửa; danh sách
    test mới theo từng crate; output `cargo test --workspace` và `clippy`.

## ACCEPTANCE CRITERIA

1. `cargo build --workspace` → exit `0`.

2. `cargo test --workspace` → exit `0`, số test ≥ 199 (baseline B2), tăng
   đúng bằng số test mới report liệt kê.

3. `cargo clippy --workspace --all-targets -- -D warnings` → exit `0`.

4. Có ít nhất 1 test chứng minh: gọi đường chạy scanner (app-tauri
   `scanner_invocation` HOẶC hàm cổng mới trong `sonar-tools` với target/scope
   mô phỏng tình huống của app-tauri) với một target NGOÀI phạm vi cho phép
   → trả lỗi/từ chối, KHÔNG trả về `CommandInvocation` runnable nào.

5. Có ít nhất 1 test tương tự #4 nhưng cho phía `sonar-cli` (`run_scanner_command`
   hoặc hàm con mới tách ra) — target ngoài phạm vi → bị chặn trước khi chạm
   `std::process::Command`.

6. Có ít nhất 1 test hồi quy xác nhận: target HỢP LỆ trong phạm vi vẫn tạo
   được `CommandInvocation` đúng như hành vi cũ (không đổi args/program cho
   nmap hoặc nuclei so với trước khi sửa) — tránh phá C2-C6 sau này.

7. `git diff --stat` → chỉ đụng `crates/sonar-tools/src/**`,
   `app/src-tauri/src/lib.rs`, `crates/sonar-cli/src/main.rs`, và các file
   test liên quan trong 3 crate đó (`app/src-tauri/src/lib.rs` chứa cả test
   module inline, không phải file riêng) + `docs/plan/*` của chính task này.
   Không đụng `app/src/` (React), `operations.rs`, `remote.rs`,
   `sonar-core/src/scanner.rs` (chỉ đọc, không sửa).

8. `git status --short` sạch ngoài các file trên; không commit, không push.

## Feedback vòng 1

**ĐẠT về mặt kỹ thuật — không cần vòng 2.** Nội dung code đúng, đã verify độc
lập (build/test/clippy đều sạch, cả 2 call site xác nhận đi qua đúng
`scanner_scope_gate` duy nhất, không còn đường né scope). Ghi lại cho hồ sơ,
KHÔNG cần worker làm lại gì:

- **Vi phạm quy trình nghiêm trọng**: worker tự `git commit` (`9c7ad58`) dù
  plan ghi rõ "Không được làm: ... Không commit". Đây không phải một sai sót
  nhỏ như thiếu ghi report (B1 vòng 3) — đây là một hành động ghi vào lịch sử
  git mà lẽ ra chỉ orchestrator được làm ở Bước 4, sau khi user xác nhận.
  Commit lần này tình cờ đúng nội dung và đúng thời điểm nên user quyết định
  giữ lại, nhưng đây KHÔNG phải tiền lệ được chấp nhận cho các vòng sau.
- Commit message có 1 ký tự lỗi encoding ("scope漏洞" thay vì tiếng Anh/Việt
  thuần) — vô hại nhưng là dấu hiệu nên rà lại message trước khi tự ý ghi vào
  lịch sử git trong tương lai (nếu launcher chưa chặn được `git commit` cục
  bộ, đây là việc cần xem lại ở `scripts/agents/run-worker.ps1`/adapter, không
  phải việc của riêng task C1).

## Feedback vòng 2

_Để trống._

## Feedback vòng 3

_Để trống._

## Feedback vòng 4

_Để trống._

## Feedback vòng 5

_Để trống._
