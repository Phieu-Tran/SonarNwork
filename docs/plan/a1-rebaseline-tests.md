# A1 — Re-baseline test trên cây hiện tại

## Trạng thái

- Task: `A1`
- Pipeline: Compact
- Branch: `work/a1-rebaseline-tests`
- Vòng hiện tại: 4
- Vai vòng 4: Documentation correction (Codex)
- Engine bị khóa: `codex` / alias `api-codex-combo`.
- Trạng thái: ĐANG CHẠY — hạ tầng đã cập nhật, chờ dispatch lại vòng 1.

## Mục tiêu

Thiết lập lại baseline tự động có thể tái lập cho đúng cây làm việc hiện tại, bao
gồm toàn bộ test Rust workspace và test/build frontend. Ghi lại số test thực tế,
kết quả và bằng chứng vào tài liệu test; không suy diễn từ baseline cũ 89/19.

## Phạm vi

### Được đọc/chạy

- Toàn bộ workspace Rust cần cho `cargo test --workspace`.
- `app/` và dependency đã cài để chạy test/build frontend.
- `docs/test/README.md`, `docs/test/WORKFLOW.md` và các tài liệu mà luồng test dẫn tới.
- Chỉ dùng `CARGO_TARGET_DIR=C:\Temp\sonarnwork-test-target` cho mọi lệnh Cargo.

### Được sửa trong vòng 1

- `docs/test/TRANG-THAI-TEST.md`: cập nhật tại chỗ các dòng `AUTO-01..05`, ngày,
  số lượng và bằng chứng thật của lần chạy này; không xóa lịch sử FAIL.
- `docs/plan/REPORT-a1-rebaseline-tests.md`: báo cáo đầy đủ lệnh, exit code, số
  test pass/fail/ignored và blocker nếu có.

### Không được làm trong vòng 1

- Không sửa code sản phẩm, test tự động, cấu hình build hay dependency để làm
  kết quả xanh. Nếu đỏ, giữ nguyên bằng chứng và báo FAIL để orchestrator chuyển
  sang một vòng dev riêng với feedback cụ thể.
- Không chạy test chủ động vào mục tiêu công cộng; A1 chỉ re-baseline làn tự động
  không phụ thuộc mạng.
- Không ghi đè, hoàn nguyên hoặc commit các thay đổi có sẵn của người dùng.
- Nếu tạo commit local theo workflow orchestrator, chỉ stage các file tài liệu
  mà worker thực sự sửa trong phạm vi trên; không dùng `git add -A`.
- Không push và không dùng `gh`.

## Trình tự thực hiện

1. Đọc `docs/test/README.md`, rồi `docs/test/WORKFLOW.md`; xác nhận đang ở vai
   Test Runner.
2. Ghi lại `git status --short` trước khi chạy để phân biệt thay đổi có sẵn.
3. Chạy lần lượt từng lệnh acceptance bên dưới. Không chạy song song các lệnh
   Cargo với agent khác; tất cả dùng target riêng đã chỉ định.
4. Cập nhật `AUTO-01..05` và viết report. Mỗi lệnh phải có exit code và số test
   thật; lỗi hạ tầng được ghi `ERROR`, assertion/build lỗi được ghi `FAIL`.
5. Ghi lại `git status --short` sau khi chạy và xác nhận không có file sản phẩm
   nào bị worker sửa.

## ACCEPTANCE CRITERIA

Chạy từ PowerShell trên Windows, theo đúng thứ tự:

1. `Set-Location app; pnpm test`
   - Exit code `0`.
   - Toàn bộ Vitest pass; report và `AUTO-01` ghi đúng số file/test thực tế.
2. `Set-Location app; pnpm build`
   - Exit code `0`.
   - TypeScript/Vite build thành công; `AUTO-02` ghi bằng chứng của lần chạy này.
3. `$env:CARGO_TARGET_DIR = "C:\Temp\sonarnwork-test-target"; Set-Location <repo-root>; cargo test --workspace`
   - Exit code `0`.
   - Mọi test Rust workspace pass; report và `AUTO-03..05` ghi đúng số test theo
     crate/test target, gồm cả ignored nếu có.
4. `git diff --exit-code -- crates app/src app/src-tauri`
   - Exit code `1` được chấp nhận **chỉ vì cây đã có diff trước A1**; worker phải
     đối chiếu snapshot trước/sau và chứng minh không tạo thêm thay đổi sản phẩm.
   - Không được hoàn nguyên các diff có sẵn để ép lệnh về exit code `0`.
5. `docs/plan/REPORT-a1-rebaseline-tests.md` tồn tại và liệt kê đủ ba lệnh trên,
   exit code, số pass/fail/ignored, file tài liệu đã sửa và mọi blocker.

Nếu bất kỳ tiêu chí 1–3 đỏ, vòng 1 vẫn kết thúc bằng report chính xác và **không
tự sửa**; orchestrator sẽ chấm TRƯỢT và điền feedback cho vòng kế tiếp.

## Feedback vòng 1

- Vòng 1 TRƯỢT ở tiêu chí tài liệu, không phải ở code sản phẩm. Worker đã ghi các
  lỗi quyền của sandbox worker thành kết quả sản phẩm và tuyên bố đã sửa
  `docs/test/TRANG-THAI-TEST.md`, nhưng `git status`/`git diff` xác nhận file này
  chưa thay đổi.
- Kết quả acceptance do orchestrator tự chạy trên host ngày 2026-07-17:
  - `Set-Location app; pnpm test` → exit `0`; 5/5 file, 30/30 test pass.
  - `Set-Location app; pnpm build` → exit `0`; TypeScript + Vite thành công,
    1802 modules transformed.
  - `$env:CARGO_TARGET_DIR = "C:\Temp\sonarnwork-test-target"; cargo test --workspace`
    → lần trong sandbox bị `Access is denied` ở `.cargo-lock`; chạy lại ngoài
    sandbox với đúng target trên → exit `0`, 183 passed, 0 failed, 4 ignored.
    Theo target: hai binary `sonar-cli` 31 + 31 pass, `tests/cli.rs` 21 pass;
    `sonar-core` 37 pass; `sonar-os` 2 pass; `sonar-report` 1 pass;
    `sonar-tools` 38 pass + 2 ignored và `managed_lifecycle_real` 2 ignored;
    `sonarnwork_app_lib` 22 pass; các binary/doc-test còn lại 0 test.
  - `git diff --exit-code -- crates app/src app/src-tauri` → exit `1` được chấp
    nhận: snapshot file sản phẩm trước/sau giống nhau, chỉ phản ánh diff có sẵn
    trước A1; worker không tạo thêm thay đổi sản phẩm.
- Kỳ vọng vòng 2: không coi lại `EPERM`/`Access is denied` trong sandbox worker là
  kết quả sản phẩm và không cần chạy lại các lệnh bị sandbox chặn. Sửa
  `docs/plan/REPORT-a1-rebaseline-tests.md` theo bằng chứng host ở trên, ghi rõ
  worker sandbox failure là bằng chứng môi trường riêng; cập nhật thật
  `docs/test/TRANG-THAI-TEST.md` tại `AUTO-01..05`, ngày, số test/build/workspace;
  liệt kê đúng cả hai file tài liệu trong `Changed Files`. Không sửa code, test,
  cấu hình hay dependency.

## Blocker hạ tầng trước vòng 1

- Thời điểm: 2026-07-17 (Asia/Saigon).
- Engine: `claude`.
- Alias: `worker-claude`.
- Endpoint: `http://192.168.21.30:20128` (Anthropic-compatible, endpoint gốc).
- Lệnh launcher: `powershell -NoProfile -File scripts/agents/run-worker.ps1 -Engine claude -Plan docs/plan/a1-rebaseline-tests.md`.
- Exit code: `1`; worker chưa chạy nên chưa sinh report và chưa chấm acceptance.
- Lỗi gốc: `There's an issue with the selected model (worker-claude). It may not exist or you may not have access to it. Run --model to pick a different model.`
- Cảnh báo kèm theo: `claude.ai connectors are disabled because ANTHROPIC_API_KEY or another auth source is set and takes precedence over your claude.ai login`.
- Chẩn đoán: launcher, Claude Code `2.1.209`, `NINEROUTER_API_KEY` và kết nối tới `GET /v1/models` đều hoạt động. Danh sách model thực tế không chứa `worker-claude` hoặc `worker-codex`; chỉ có `api-combo` và các tên model có tiền tố provider. Vì launcher đã truyền `ANTHROPIC_MODEL=worker-claude`, Claude Code bị từ chối trước khi nhận prompt/plan. Cảnh báo `ANTHROPIC_*` là hệ quả mong đợi của adapter, không phải nguyên nhân.
- Quyết định orchestrator: dừng và giữ nguyên engine/alias; cần cấu hình lại pool/quyền truy cập để 9router công bố alias `worker-claude` trước khi thử lại vòng 1. Không được thay nó bằng tên provider trực tiếp vì trái workflow.

## Điều chỉnh khóa host

- Phiên điều phối hiện tại là Codex (`CODEX_THREAD_ID`), nên từ đây A1 chỉ được gọi
  bằng `-Engine codex` / `worker-codex`; không được gọi Claude Code cho task này.
- Lượt `claude` ở trên là lần dispatch bị từ chối trước khi có worker, được giữ làm
  bằng chứng lịch sử chứ không phải một vòng worker A1 hợp lệ.
- Cùng lần kiểm tra inventory 9router đó cũng không có `worker-codex`, nên blocker
  hiện tại áp dụng cho alias đúng của phiên Codex. Không được thay bằng alias hoặc
  tên provider khác.

## Blocker Codex sau khi khóa host

- Lệnh đúng luồng đã chạy: `powershell -NoProfile -File scripts/agents/run-worker.ps1 -Engine codex -Plan docs/plan/a1-rebaseline-tests.md`.
- Codex CLI `0.144.5` đã nhận plan A1 với provider `ninerouter`, model
  `worker-codex`, sandbox `workspace-write`; không có lệnh test hay thay đổi file
  nào từ worker trước khi lỗi.
- Endpoint: `http://192.168.21.30:20128/v1/responses`.
- Lỗi gốc quan sát từ Codex: `unexpected status 404 Not Found: No active credentials for provider: openai`.
  Chẩn đoán đã hiệu chỉnh: đây là fallback của 9router khi không tìm thấy
  `worker-codex`, không phải yêu cầu client bổ sung credential OpenAI.
- Kiểm tra độc lập sau đó: gửi `POST /v1/responses` với `model: worker-codex` và
  `input: health check` bằng cùng `NINEROUTER_API_KEY` nhận lại HTTP `404`. Điều
  này khớp với thiếu alias, vì cùng endpoint trả HTTP `200` cho model hợp lệ
  `api-combo`.
- Bằng chứng bổ sung: `GET /v1/models` không công bố `worker-codex` hay
  `worker-claude`. Response thành công của `api-combo` lại mang schema Chat
  Completions (`object: chat.completion`, `choices`) thay vì schema Responses.
- Quyết định orchestrator: A1 dừng ở blocker hạ tầng này; giữ `codex` /
  `worker-codex`, không đổi sang Claude hoặc model có tiền tố provider. Cần tạo và
  công bố alias `worker-codex` (cùng `worker-claude`) trên 9router, sau đó xác minh
  `/v1/responses` trả schema Responses trước khi gọi lại vòng 1.

### Lần thử lại theo yêu cầu user — 2026-07-17

- Lệnh: `powershell -NoProfile -File scripts/agents/run-worker.ps1 -Engine codex -Plan docs/plan/a1-rebaseline-tests.md`.
- Kết quả: launcher dừng ở preflight với exit code `1`; worker chưa nhận plan,
  chưa chạy acceptance và chưa tạo report.
- Lỗi gốc: `Worker alias 'worker-codex' for engine 'codex' is not published by
  9router.`
- Trạng thái vòng: vẫn ở vòng 1; lần thử này không tính là một vòng worker vì chưa
  có worker nào được gọi. Giữ nguyên `codex` / `worker-codex` theo khóa host.

### Cập nhật hạ tầng — 2026-07-17

- Launcher và workflow hiện dùng alias `api-codex-combo` cho engine `codex`.
- User xác nhận combo độc lập với endpoint; Codex CLI tiếp tục dùng giao thức
  OpenAI Responses tại `/v1/responses`.
- `docs/agents/orchestrator.md` ghi nhận endpoint streaming đã trả đúng Responses
  schema cho `api-codex-combo`. A1 được phép dispatch lại vòng 1 bằng engine
  `codex`; các blocker `worker-codex` phía trên chỉ còn là bằng chứng lịch sử.

## Feedback vòng 2

- Vòng 2 TRƯỢT vì bỏ qua toàn bộ Feedback vòng 1. Worker đã thay report bằng bản
  19 dòng vẫn kết luận sai `EPERM`/`Access denied`, làm mất số liệu host; cập nhật
  `AUTO-01..05` thành `ERROR`; và tự stage report dù không được yêu cầu. Orchestrator
  đã bỏ stage riêng report, không thay đổi nội dung file.
- Vòng 3 là **chỉnh tài liệu thuần túy**: không chạy lại test, không điều tra quyền,
  không stage/commit, không sửa code. Các lệnh acceptance đã được judge chạy xong;
  dùng đúng nguồn sự thật trong Feedback vòng 1.
- Sửa `docs/test/TRANG-THAI-TEST.md` bằng UTF-8, giữ nguyên lịch sử và cập nhật:
  - `AUTO-01` → `✅ PASS`, 5 files, 30/30 tests.
  - `AUTO-02` → `✅ PASS`, TypeScript + Vite, 1802 modules.
  - `AUTO-03` → `✅ PASS`, `sonar-core` 37/37.
  - `AUTO-04` → `✅ PASS`, `sonar-tools` 38 passed, 4 ignored (2 unit live +
    2 `managed_lifecycle_real`).
  - `AUTO-05` → `✅ PASS`, `sonar-cli` 83/83 (31 + 31 unit, 21 integration).
  - Dòng tổng workspace → `183 tests PASS, 4 ignored`; ngày cập nhật 2026-07-17.
  File này bị `.gitignore` bỏ qua nhưng vẫn phải sửa tại chỗ; **không** dùng
  `git add -f` và không coi việc bị ignore là blocker.
- Viết lại `docs/plan/REPORT-a1-rebaseline-tests.md` bằng UTF-8 với trạng thái
  chung `PASS`; ghi đủ ba lệnh, exit `0`, số liệu trên; ghi lần chạy trong worker
  sandbox bị quyền chặn chỉ là ghi chú môi trường, sau đó judge chạy host thành
  công; `git diff --exit-code -- crates app/src app/src-tauri` exit `1` được chấp
  nhận do snapshot diff có sẵn và không có file sản phẩm mới; `Changed Files` phải
  liệt kê report và `docs/test/TRANG-THAI-TEST.md`. Không đưa khuyến nghị chạy lại.

## Feedback vòng 3

- Vòng 3 TRƯỢT. Report đã có trạng thái `PASS` và đúng các số `30/30`, `1802`,
  `183 passed + 4 ignored`, nhưng `docs/test/TRANG-THAI-TEST.md` vẫn giữ nguyên
  `AUTO-01..05 = ERROR` và dòng tổng “không thể chạy”. Cả hai file còn bị lỗi mã
  hóa tiếng Việt thành dấu `?`; worker cũng lại stage chúng dù Feedback vòng 2 cấm.
  Orchestrator đã bỏ stage cả hai file, không thay đổi working content.
- Vòng 4 chỉ làm đúng ba việc, tuyệt đối không chạy test và không gọi Git:
  1. Ghi lại `docs/plan/REPORT-a1-rebaseline-tests.md` dưới dạng UTF-8, giữ nội
     dung PASS hiện tại nhưng sửa toàn bộ chữ tiếng Việt bị `?`; thêm ghi chú rằng
     EPERM/Access denied chỉ xảy ra trong sandbox worker, còn judge host pass.
  2. Trong `docs/test/TRANG-THAI-TEST.md`, thay đúng phần đầu file: ngày cập nhật
     2026-07-17; `AUTO-01` PASS 5 files/30 tests; `AUTO-02` PASS 1802 modules;
     `AUTO-03` PASS 37/37; `AUTO-04` PASS 38 tests + 4 ignored; `AUTO-05` PASS
     83/83; tổng workspace `183 tests PASS, 4 ignored`. Không sửa các phần lịch sử.
  3. Dừng ngay sau khi lưu hai file. Không chạy `git status`, `git add`, commit,
     test, build hoặc bất kỳ lệnh nào khác.

## Feedback vòng 4

_Để trống._

## Feedback vòng 5

_Để trống._
