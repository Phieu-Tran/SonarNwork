# C2 — Nối httpx vào contract C1 (parser output thật)

## Trạng thái

- Task: `C2`
- Pipeline: Full
- Branch: `work/c2-httpx-parser`
- Vòng hiện tại: 2
- Engine: `claude` / alias `api-combo`
- Trạng thái: TRƯỢT vòng 1 (regression thật: `output.raw` không được set, phá
  UI raw-output view — xem Feedback vòng 1). Không có commit trái phép (đúng
  yêu cầu, đã học từ C1). Chờ dispatch vòng 2.

## Bối cảnh — đã điều tra trước, phần lớn httpx ĐÃ hoạt động

Orchestrator đã nghiên cứu trước khi ra đề, không cần worker dò lại từ đầu:

- **Đã có sẵn, KHÔNG cần đụng**: `httpx_invocation` (`crates/sonar-core/src/scanner.rs:224-246`)
  build args httpx thật, hợp lý (`-u <target> -silent -json -status-code
  -title -tech-detect -follow-redirects -timeout 10 -retries 1 -threads 10
  -rate-limit 20`). Descriptor + install strategy (`AutoDownload` từ
  `projectdiscovery/httpx`) đã có trong `sonar-tools/src/lib.rs:396-411`.
  Scope check qua `scanner_scope_gate` (C1, vừa merge) đã tự động áp dụng cho
  Httpx vì gate không phân biệt theo kind. Có test khoá invocation
  (`catalog_scanners_have_single_target_bounded_invocations`,
  `scanner.rs:692-730`, đã pass). **Không có gì để làm ở phần dò-runtime,
  preview, hay chạy-có-phạm-vi — cả ba đã ĐẠT nhờ C1.**
- **CÒN THIẾU, đây là việc thật của C2**: `summarize_scanner_output`
  (`scanner.rs:444-460`) route `Httpx` vào `summarize_json_lines`
  (`scanner.rs:462-493`) — hàm này KHÔNG parse JSON, chỉ đếm số dòng
  stdout không rỗng rồi nhét nguyên văn vào `output.raw`. Không đọc bất kỳ
  field nào của httpx (`url`, `status_code`, `title`, `tech`, `webserver`).
  So sánh với `summarize_nuclei` (`scanner.rs:594-626`) — ĐÃ parse JSON từng
  dòng, trích `severity`, có test khoá riêng
  (`summarizes_nuclei_jsonl_findings`, `scanner.rs:779-788`). **httpx chưa có
  parser tương đương, chưa có test nào feed sample output JSON thật vào
  `summarize_scanner_output` — đây chính là lỗ hổng MASTERPLAN §4 yêu cầu
  đóng ("test tất định khóa parse").**

## Mục tiêu

1. Viết `summarize_httpx` (đặt tên tuỳ worker, theo đúng phong cách
   `summarize_nuclei`) trong `crates/sonar-core/src/scanner.rs`: parse mỗi
   dòng stdout là một JSON object (định dạng `httpx -json`, mỗi dòng 1 host),
   trích tối thiểu: `url`, `status_code`, `title` (có thể rỗng/thiếu),
   `tech`/`technologies` (mảng string, có thể rỗng/thiếu), `webserver` (có
   thể rỗng/thiếu). Dòng không parse được (JSON hỏng, dòng trống) phải bị bỏ
   qua AN TOÀN — không panic, không crash toàn bộ summary (đúng tinh thần
   `summarize_nuclei` dùng `if let Ok(value) = serde_json::from_str(...)`).
2. Route `ExternalScannerKind::Httpx` sang hàm mới trong
   `summarize_scanner_output` (dòng 453-458 hiện gộp chung Httpx với
   Naabu/Subfinder/Dnsx/Trippy/Nexttrace) — TÁCH RIÊNG Httpx, GIỮ NGUYÊN
   Naabu/Subfinder/Dnsx/Trippy/Nexttrace vẫn dùng `summarize_json_lines` như
   cũ (không phải việc của C2 — đó là C3-C6 sau này nếu cần).
3. `output.summary_rows` cho httpx nên có tối thiểu: số host phản hồi
   (`total`), số host status 2xx (hoặc liệt kê status code phân bố — tự
   quyết định mức chi tiết hợp lý, tham khảo cách nuclei làm với "Findings"/
   "High/Critical"), có thể thêm 1 dòng liệt kê tiêu đề/tech phát hiện được
   nếu ngắn gọn. `summary` (chuỗi tóm tắt 1 dòng) phải phản ánh đúng số host
   thật parse được, không phải số dòng thô.
4. Test tất định (offline, không cần binary httpx thật, không cần mạng): tạo
   sample stdout JSON giả lập đúng format httpx `-json` thật (worker tự tra
   cứu format thật của `projectdiscovery/httpx -json` nếu không chắc field
   name — ví dụ tối thiểu `{"url":"https://example.com","status_code":200,"title":"Example","tech":["nginx"],"webserver":"nginx"}`),
   feed vào `summarize_scanner_output(ExternalScannerKind::Httpx, ...)`,
   assert đúng số liệu trong `summary_rows`. Thêm ít nhất 1 test case dòng
   JSON hỏng/trống lẫn trong output — xác nhận không panic, các dòng hợp lệ
   khác vẫn được đếm đúng.

## Phạm vi

### Được sửa trong vòng 1

- `crates/sonar-core/src/scanner.rs`: thêm hàm parser mới + sửa route trong
  `summarize_scanner_output` + test mới trong `#[cfg(test)] mod tests` cuối
  file (đã có sẵn, dòng 628+).

### Không được làm

- KHÔNG đụng `httpx_invocation`, mode/port handling của httpx (đã đúng,
  không cần sửa — xem "Bối cảnh").
- KHÔNG đụng Nmap/Nuclei/Naabu/Subfinder/Dnsx/Trippy/Nexttrace — chỉ tách
  riêng route cho Httpx, các kind khác giữ nguyên hành vi cũ.
- KHÔNG sửa `scanner_scope_gate`, `sonar-tools/src/lib.rs`, `app/src-tauri/src/lib.rs`,
  `crates/sonar-cli/src/main.rs` — không cần, C1 đã đủ cho phần scope/run.
- KHÔNG tải/chạy binary httpx thật, KHÔNG cần mạng cho bất kỳ test nào của
  vòng này — tất cả test phải tất định dựa trên sample JSON viết tay.
- Không push, không commit — để orchestrator commit ở Bước 4 (**LƯU Ý: vòng
  C1 trước worker đã tự ý commit, đây là vi phạm quy trình — vòng này TUYỆT
  ĐỐI không lặp lại**).

## Trình tự thực hiện

1. Đọc `crates/sonar-core/src/scanner.rs` dòng 440-630 (toàn bộ khối
   `summarize_scanner_output` + `summarize_json_lines` + `summarize_nmap` +
   `summarize_nuclei`) để nắm đúng phong cách và kiểu `ProbeOutput`/`SummaryRow`.
2. Viết hàm parser mới cho httpx, theo đúng mẫu `summarize_nuclei`.
3. Sửa match arm trong `summarize_scanner_output` để route riêng `Httpx`.
4. Viết test: ít nhất 2 case — (a) sample output hợp lệ nhiều dòng, đếm đúng
   số host/status/tech; (b) lẫn dòng hỏng/trống, không panic, số liệu vẫn
   đúng cho các dòng hợp lệ còn lại.
5. `cargo test -p sonar-core` → toàn bộ pass, gồm test mới.
6. `cargo test --workspace` → không giảm test so với baseline C1 (202
   passed, 4 ignored), tăng đúng số test mới thêm.
7. `cargo clippy --workspace --all-targets -- -D warnings` → 0 cảnh báo.
8. Viết `docs/plan/REPORT-c2-httpx-parser.md` bằng tool ghi file thật
   (Write/Edit), liệt kê: tên hàm mới, vị trí, sample test dùng, kết quả
   `cargo test --workspace` và `clippy`.

## ACCEPTANCE CRITERIA

1. `cargo build --workspace` → exit `0`.
2. `cargo test -p sonar-core` → exit `0`, toàn bộ pass, gồm ≥ 2 test mới cho
   parser httpx (case hợp lệ + case dòng hỏng).
3. `cargo test --workspace` → exit `0`, số test ≥ 202 (baseline C1), tăng
   đúng bằng số test mới report liệt kê.
4. `cargo clippy --workspace --all-targets -- -D warnings` → exit `0`.
5. Test mới PHẢI thật sự gọi `summarize_scanner_output(ExternalScannerKind::Httpx, ...)`
   (không test hàm parser nội bộ một mình, tách rời khỏi đường dẫn thật) —
   đảm bảo phủ đúng đường dẫn production dùng.
6. `git diff --stat` → CHỈ đụng `crates/sonar-core/src/scanner.rs` (+
   `docs/plan/*` của chính task này). Không file nào khác bị đổi.
7. `git status --short` sạch ngoài các file trên; **không commit, không
   push** (worker tự kiểm tra `git log --oneline -3` trước khi kết thúc phiên
   để chắc chắn không có commit mới nào bị tạo ra ngoài ý muốn).

## Feedback vòng 1

**TRƯỢT — build/test/clippy đều sạch và logic parse đúng, nhưng có 1
regression thật cần sửa trước khi ĐẠT.**

- Logic tốt: `summarize_httpx` parse JSON đúng, skip dòng hỏng an toàn
  (không panic), 3 test mới đều gọi đúng `summarize_scanner_output` (đường
  dẫn production), test hồi quy các kind khác (Nmap/Nuclei/Naabu/...) không
  bị đụng. Không có commit trái phép — đúng yêu cầu.
- **Regression**: `summarize_httpx` (hàm mới, `crates/sonar-core/src/scanner.rs`)
  KHÔNG set `output.raw` (kiểu `Option<serde_json::Value>`, định nghĩa ở
  `crates/sonar-core/src/probe.rs:105`). Trong khi đó `summarize_nmap`
  (`scanner.rs:537-543`) và `summarize_json_lines` cũ mà Httpx từng dùng
  (`scanner.rs:486-491`) đều set `output.raw = Some(json!({...}))` với tối
  thiểu `tool`/`exit_code`/`stdout`/`stderr`. Frontend `app/src/App.tsx:4650-4662`
  (`commandOutputFromRaw(result.output.raw)` rồi fallback
  `formatJsonOutput(result.output.raw ?? result)`) DÙNG field này để hiển thị
  "raw output" cho người dùng khi họ mở xem chi tiết một lần chạy scanner.
  Trước khi sửa C2, httpx có `raw` (qua nhánh generic cũ). Sau khi sửa,
  `raw` sẽ là `None` cho MỌI lần chạy httpx — người dùng mở "raw output" cho
  kết quả httpx sẽ thấy dữ liệu fallback sai lệch thay vì stdout/stderr thật.
  Đây là quy trình đã hoạt động trước khi C2 chạm vào, không phải tính năng
  mới cần thêm — TUYỆT ĐỐI không được làm mất.

- **Sửa chính xác**: thêm `output.raw = Some(json!({ ... }))` vào cuối
  `summarize_httpx`, tối thiểu gồm `tool` (= `"httpx"` hoặc
  `ExternalScannerKind::Httpx.tool_id()`), `exit_code`, `stdout`, `stderr` —
  đúng cấu trúc `summarize_json_lines` đã dùng (`scanner.rs:486-491`) để
  frontend không cần đổi gì. Có thể bổ sung thêm các field đã parse
  (`hosts`, `status_codes`, `technologies`) nếu muốn, miễn giữ nguyên 4 field
  gốc để không phá hành vi hiện có của `commandOutputFromRaw`/`formatJsonOutput`
  phía frontend (không cần sửa file TypeScript nào — chỉ cần backend trả
  đúng shape JSON tương thích).
- **Kỳ vọng vòng 2**: thêm đúng phần `output.raw` còn thiếu, KHÔNG đổi gì
  khác trong `summarize_httpx` (parse logic, summary_rows đã đúng, giữ
  nguyên). Thêm 1 test mới xác nhận `output.raw` có mặt và chứa đúng
  `stdout`/`stderr`/`exit_code` cho một sample httpx hợp lệ. Chạy lại toàn
  bộ `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`.
  Không commit.

## Feedback vòng 2

_Để trống._

## Feedback vòng 3

_Để trống._

## Feedback vòng 4

_Để trống._

## Feedback vòng 5

_Để trống._
