# A4 — Dọn .mcp.json + Đồng bộ README & docs/design

## Trạng thái

- Task: `A4`
- Pipeline: Direct
- Branch: `work/a4-cleanup-docs`
- Vòng hiện tại: 1 (ĐẠT)
- Engine: `claude` / alias `api-combo`
- Trạng thái: ✅ PASS — xác minh lại bởi orchestrator 2026-07-17 (pnpm test 30/30,
  pnpm build 1802 modules, cargo test --workspace 185 passed/4 ignored, README +
  docs/design đã cập nhật, .mcp.json quyết định track). Chờ user xác nhận Bước 4.

## Mục tiêu

Hoàn tất EPIC A bằng cách:
1. Quyết định `.mcp.json` track hay ignore (giải thích rõ trong commit message hoặc .gitignore)
2. Cập nhật README.md để ghi nhận TUI redesign (gõ lệnh trực tiếp, Ctrl+P workflow browser)
3. Cập nhật README để ghi nhận mô hình an toàn mới (bounded profiles + risk labels thay "scope confirmation")
4. Đồng bộ `docs/design/pages/{operations,tools}.md` với hành vi mới từ A2/A3
5. Chạy `pnpm build` xác minh không có lỗi TypeScript/Vite

## Phạm vi

### Được sửa trong vòng 1

- `README.md`: thêm/cập nhật section về TUI redesign + bounded profiles model
- `docs/design/pages/operations.md`: ghi nhận bounded profiles (safe/medium/high risk)
- `docs/design/pages/tools.md`: ghi nhận scanner risk labels
- `.mcp.json`: quyết định track (ghi lý do) hoặc ignore (thêm vào `.gitignore`)
- Test vẫn pass, build vẫn xanh

### Không được làm

- Sửa code sản phẩm (Rust/TypeScript)
- Thêm tính năng mới
- Commit hay push

## Trình tự thực hiện

1. Đọc lại `README.md` dòng "Under the hood" và các section design
2. Xác nhận hiểu đúng TUI redesign từ A2 + bounded profiles từ A3
3. Cập nhật README: thêm description về "gõ lệnh trực tiếp trong TUI" + "risk-aware profiles"
4. Kiểm tra `docs/design/pages/operations.md` và `tools.md` xem cần cập nhật gì cho risk model
5. Quyết định `.mcp.json`: 
   - Nếu track: ghi ghi chú lý do (ví dụ: "MCP configuration cho IDE integration")
   - Nếu ignore: thêm `??.mcp.json` vào `.gitignore`
6. Chạy `pnpm test` + `pnpm build` xác minh
7. Chạy `cargo test --workspace` xác minh số test không giảm (≥ 185)

## ACCEPTANCE CRITERIA

Chạy từ PowerShell, thứ tự:

1. `Set-Location app; pnpm test`
   - Exit code `0`.
   - Vitest pass (30/30 hoặc ≥ A1 baseline).

2. `Set-Location app; pnpm build`
   - Exit code `0`.
   - TypeScript + Vite build thành công (≥ 1802 modules).

3. `cargo test --workspace`
   - Exit code `0`.
   - Số test ≥ 185 (A3 baseline).

4. Audit `.mcp.json`:
   - Hoặc `.mcp.json` được track + ghi lý do trong commit message
   - Hoặc `.mcp.json` thêm vào `.gitignore` + ghi lý do

5. README.md updated:
   - Section "Under the hood" ghi nhận TUI redesign
   - Ghi nhận bounded profiles + risk labels model

6. docs/design pages updated:
   - `operations.md`: ghi risk labels cho scanner profiles
   - `tools.md`: ghi bounded profile concept

7. `git diff --exit-code -- app crates` → chỉ tài liệu được sửa (README, docs/design, .gitignore nếu); không code sản phẩm

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
