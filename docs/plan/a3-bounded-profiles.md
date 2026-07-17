# A3 — Chốt mô hình an toàn "bounded profiles + risk labels"

## Trạng thái

- Task: `A3`
- Pipeline: Full
- Branch: `work/a3-bounded-profiles`
- Vòng hiện tại: 1
- Engine: `claude` / alias `api-combo`
- Trạng thái: PENDING — chờ dispatch vòng 1

## Mục tiêu

Hoàn thiện mô hình an toàn mới thay thế "scope confirmation" bằng "bounded profiles + risk labels". Đảm bảo sonar-core/interaction.rs + sonar-tools logic nhất quán, không còn mâu thuẫn, test khóa hành vi risk-labeling của scanner/probe.

Cụ thể:
- Không còn boolean `scope_confirmed` ở scanner invocation
- Mỗi tool (scanner/probe) có profile mặc định an toàn + profile alternative cao rủi ro
- Profile được nhãn với risk level (safe, medium, high)
- App/CLI ghi nhận risk và hướng dẫn user

## Phạm vi

### Được sửa trong vòng 1

- `crates/sonar-core/src/interaction.rs`: entity types, probe + scanner descriptors, risk labels, profile model
- `crates/sonar-tools/src/lib.rs`, `operations.rs`, `remote.rs`: tool lifecycle, invocation dispatcher, scope rules theo profile
- Test trong `crates/sonar-core/tests/`, `crates/sonar-tools/tests/`: thêm test khóa risk-label behavior
- README.md, docs/design/pages nếu ghi nhận mô hình mới
- Bump `interaction.rs` schema_version nếu contract thay đổi

### Không được làm

- Thêm công cụ ngoài mới (C-series)
- Sửa TUI logic (A2 đã chốt)
- Thay đổi data persistence
- Commit hay push

## Trình tự thực hiện

1. Đọc toàn bộ `crates/sonar-core/src/interaction.rs` để hiểu schema hiện tại: entity, probe, scanner, descriptor
2. Kiểm tra `sonar-tools/src/lib.rs` + `operations.rs` + `remote.rs` để dò tàn dư "scope_confirmed" boolean
3. Rà `crates/sonar-core/src/probe.rs` để hiểu risk model của probe (nếu có)
4. Xác định những tool/probe nào là high-risk (scanner intrusive, remote check) và nên có profile alternative
5. Nếu code đã nhất quán: ghi tài liệu + viết test để khóa hành vi. Nếu còn mâu thuẫn: sửa code để nhất quán
6. Chạy `cargo test -p sonar-core` + `cargo test -p sonar-tools` xác nhận pass
7. Chạy `cargo test --workspace` xác nhận ≥ 183

## ACCEPTANCE CRITERIA

Chạy từ PowerShell, thứ tự:

1. `cargo test -p sonar-core --all-targets`
   - Exit code `0`.
   - Toàn bộ sonar-core test pass (unit + integration).

2. `cargo test -p sonar-tools --all-targets`
   - Exit code `0`.
   - Toàn bộ sonar-tools test pass; gồm lifecycle, profile, risk-label test.

3. `cargo test --workspace`
   - Exit code `0`.
   - Mọi test pass; số test ≥ 183 (không giảm so với A1).

4. Code audit: xác nhận sau khi sửa
   - Grep "scope_confirmed" trong `crates/sonar-{core,tools}` → không còn boolean mâu thuẫn
   - Mỗi scanner/probe high-risk có risk_label ghi rõ hoặc default profile safe
   - Có test khóa: ví dụ "nuclei_profile_restricts_intrusive_templates" hay "scanner_fast_profile_uses_bounded_port_range"

5. Schema check:
   - Nếu contract InteractionCatalog / ManagedToolDescriptor đổi → schema_version ++ trong interaction.rs
   - `interaction.rs` + test `interaction_catalog_schema_*` pass

6. `cargo clippy --workspace --all-targets -- -D warnings`
   - Exit code `0` hoặc cảnh báo được chấp nhận nếu từ A1

7. `git diff --exit-code -- crates app/src-tauri/src/lib.rs` → chỉ chứa file sửa (interaction.rs, lib.rs, operations.rs, remote.rs); không sửa sản phẩm vô ý

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
