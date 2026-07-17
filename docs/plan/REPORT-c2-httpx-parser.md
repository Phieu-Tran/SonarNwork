# REPORT — C2: Nối httpx vào contract C1 (parser output thật)

## Trạng thái

- Task: `C2`
- Branch: `work/c2-httpx-parser`
- Kết quả: **HOÀN THÀNH**

## Thay đổi

### File duy nhất: `crates/sonar-core/src/scanner.rs`

116 lines added, 2 lines changed.

#### 1. Tách route Httpx khỏi nhóm generic

Trước: `Httpx | Naabu | Subfinder | Dnsx | Trippy | Nexttrace` tất cả đi vào `summarize_json_lines`.

Sau: `Httpx` riêng vào `summarize_httpx(...)`, các kind khác giữ nguyên như cũ.

#### 2. `summarize_httpx` — hàm parser mới

Vị trí: ngay sau `summarize_scanner_output`, trước `summarize_json_lines`.

Logic:
- Mỗi dòng stdout là 1 JSON object (`httpx -json` format), parse bằng `serde_json::from_str::<serde_json::Value>`.
- Dòng rỗng hoặc JSON hỏng → skip, không panic (giống `summarize_nuclei`).
- Trích fields: `status_code` (BTreeMap phân bố), `tech` / `technologies` (BTreeSet, hỗ trợ cả 2 tên field).
- `summary_rows`: Hosts (total), Status 2xx/4xx/... (phân bố), Technologies (nếu có).
- `summary`: 1 dòng tóm tắt host count / status code count / tech count.

#### 3. 3 test mới

| Test | Purpose |
|---|---|
| `summarizes_httpx_multiline_jsonl_output` | 3 dòng JSON hợp lệ (2x200, 1x403), 2 techs. Assert: total=3, phân bố status, techs merged sorted. |
| `summarizes_httpx_skips_malformed_json_lines` | 5 dòng: 2 hợp lệ + 2 malformed + 1 empty. Assert: total=2, phân bố status đúng cho lines hợp lệ. |
| `summarizes_httpx_empty_output` | stdout rỗng. Assert: total=0, summary chứa "0 host". |

Tất cả test gọi `summarize_scanner_output(ExternalScannerKind::Httpx, ...)` — phủ đúng đường dẫn production.

## Kết quả test

### `cargo test -p sonar-core`
- **41 passed, 0 failed, 2 ignored**
- Sonar-core tăng từ 38 → 41 (3 test mới)

### `cargo test --workspace`
- **Exit 0**, tất cả pass, không regress

### `cargo clippy --workspace --all-targets -- -D warnings`
- **Exit 0**, 0 cảnh báo

## Git status

- `git diff --stat`: **chỉ** `crates/sonar-core/src/scanner.rs` (+116/-2)
- `git log --oneline -3`: không có commit mới (giữ nguyên `e5e9e78`)
- `git status --short`: working tree sạch ngoài file plan + scanner.rs

## Blockers

Không có.
