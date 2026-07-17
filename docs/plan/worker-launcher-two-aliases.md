# Hạ tầng worker — launcher chung với hai alias

> **Đã lỗi thời (tên alias).** File này là đề bài gốc của vòng orchestrator đã
> ĐẠT — giữ lại làm biên bản lịch sử (xem quy ước ở
> [`MASTERPLAN.md`](MASTERPLAN.md) mục 5), không phải tài liệu sống. Tên alias
> `worker-claude`/`worker-codex` mô tả bên dưới **đã đổi tên** trong dashboard
> 9router thành `api-combo`/`api-codex-combo`. Nguồn sự thật hiện tại cho tên
> alias, biến môi trường và lệnh launcher là
> [`../agents/orchestrator.md`](../agents/orchestrator.md) và
> [`../../scripts/agents/run-worker.ps1`](../../scripts/agents/run-worker.ps1).

## Mục tiêu

Thay đoạn gọi worker gắn chặt với Claude Code trong workflow orchestrator bằng
một launcher PowerShell trung lập. Launcher hỗ trợ hai engine độc lập nhưng dùng
chung 9router, key, hợp đồng plan/report và chính sách an toàn:

- Claude Code → alias `worker-claude` qua Anthropic-compatible endpoint.
- Codex CLI → alias `worker-codex` qua OpenAI Responses-compatible endpoint.

Các biến `ANTHROPIC_*` chỉ được tồn tại bên trong adapter Claude, không còn là
cấu hình công khai mà orchestrator phải tự thiết lập.

## Phạm vi được sửa

- Thêm `scripts/agents/run-worker.ps1`.
- Cập nhật `docs/agents/orchestrator.md` để gọi launcher chung.
- Có thể thêm tài liệu ngắn dưới `scripts/agents/` nếu thật sự cần cho cách dùng.
- Không sửa code sản phẩm dưới `app/` hoặc `crates/`.
- Không hoàn nguyên, stage hoặc commit các thay đổi có sẵn của người dùng.

## Hợp đồng launcher

`scripts/agents/run-worker.ps1` phải có tối thiểu:

- `-Engine claude|codex` (bắt buộc).
- Khóa engine theo host: Claude Code chỉ cho `-Engine claude`; Codex chỉ cho
  `-Engine codex`. Launcher nhận diện qua marker phiên (`CLAUDECODE` /
  `CLAUDE_CODE_ENTRYPOINT` hoặc `CODEX_THREAD_ID`) và từ chối engine chéo trước
  khi gọi model. Ngoài phiên agent, `-OrchestratorHost claude|codex` là bắt buộc
  để automation khai báo host; nó vẫn phải khớp `-Engine`.
- `-Plan <đường-dẫn>` (bắt buộc, phải tồn tại và nằm trong repo).
- `-DryRun` để kiểm tra cấu hình/lệnh mà không gọi model.
- Cấu hình trung lập:
  - `NINEROUTER_BASE_URL`, mặc định `http://192.168.21.30:20128`.
  - `NINEROUTER_API_KEY`, bắt buộc khi chạy thật, không hardcode/không in ra.
  - `NINEROUTER_CLAUDE_ALIAS`, mặc định `worker-claude`.
  - `NINEROUTER_CODEX_ALIAS`, mặc định `worker-codex`.
- Chỉ có đúng hai alias mặc định. Với Claude Code, cả model chính và small/fast
  cùng dùng `worker-claude`, không tạo alias thứ ba.
- Trước khi chạy thật, launcher xác minh alias đã chọn có trong `GET /v1/models`.
  Thiếu alias là blocker cấu hình 9router; không coi thông báo provider fallback là
  lỗi credential client và không thay ngầm bằng model khác.
- Tự sinh prompt chuẩn từ đường dẫn plan: chỉ làm trong phạm vi plan, test sau
  thay đổi, commit local có chọn lọc, viết `REPORT-<tên-plan>.md`, không push/gh.
- Trả nguyên exit code của CLI worker.

## Adapter Claude Code

- Nội bộ ánh xạ base URL gốc (không `/v1`) sang `ANTHROPIC_BASE_URL`, key sang
  `ANTHROPIC_AUTH_TOKEN`, và alias sang `ANTHROPIC_MODEL` cùng
  `ANTHROPIC_SMALL_FAST_MODEL`.
- Gọi `claude -p` với prompt là positional argument trước option variadic
  `--disallowedTools`, tránh lỗi prompt bị hiểu thành deny-rule.
- Giữ chặn `Bash(git push:*)` và `Bash(gh:*)`.

## Adapter Codex CLI

- Dùng endpoint `<NINEROUTER_BASE_URL>/v1` và custom provider `ninerouter` với
  `wire_api = "responses"`, `env_key = "NINEROUTER_API_KEY"`.
- Endpoint phải trả schema Responses (`object: "response"` với `output`), không
  chỉ trả HTTP `200` hoặc schema Chat Completions (`choices`).
- Gọi `codex exec --sandbox workspace-write --ephemeral` và alias
  `worker-codex` bằng `--model`/`-m`.
- Tắt network cho các lệnh do worker sinh bằng
  `sandbox_workspace_write.network_access=false`; việc gọi model của Codex host
  vẫn dùng endpoint provider.
- Không truyền key vào prompt/log; giữ bộ lọc môi trường mặc định và loại rõ
  `NINEROUTER_API_KEY`, `ANTHROPIC_*`, `CODEX_API_KEY` khỏi subprocess shell.
  Khi truyền mảng này bằng `--config` trên Windows, dùng string TOML trong đó mỗi
  phần tử là literal string (`['NINEROUTER_API_KEY', ...]`) để giữ đúng kiểu array.

## Cập nhật workflow

`docs/agents/orchestrator.md` phải:

- Mô tả hai alias, cùng pool/failover nhưng khác wire protocol.
- Khóa ánh xạ Claude Code → `worker-claude` và Codex → `worker-codex`; không để
  orchestrator tự chọn engine chéo hoặc đổi engine sau lỗi.
- Nói rõ `worker-codex` chỉ chạy khi 9router hỗ trợ `/v1/responses`.
- Thay block thiết lập `ANTHROPIC_*` bằng hai ví dụ launcher:
  - `powershell -NoProfile -File scripts/agents/run-worker.ps1 -Engine claude -Plan <plan>`
  - `powershell -NoProfile -File scripts/agents/run-worker.ps1 -Engine codex -Plan <plan>`
- Không tự đổi engine/alias giữa các vòng khi provider lỗi; báo đúng blocker.

## ACCEPTANCE CRITERIA

1. Parse cú pháp PowerShell không có lỗi:

   ```powershell
   $errors = $null
   [void][System.Management.Automation.Language.Parser]::ParseFile(
     (Resolve-Path scripts/agents/run-worker.ps1), [ref]$null, [ref]$errors
   )
   if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }
   ```

2. Claude dry-run:

   ```powershell
   powershell -NoProfile -File scripts/agents/run-worker.ps1 `
     -Engine claude -Plan docs/plan/a1-rebaseline-tests.md -DryRun
   ```

   Exit `0`; output có `worker-claude`, endpoint gốc và tên plan; không chứa giá
   trị `NINEROUTER_API_KEY`, không có `/v1` ở Claude endpoint.

3. Codex dry-run:

   ```powershell
   powershell -NoProfile -File scripts/agents/run-worker.ps1 `
     -Engine codex -Plan docs/plan/a1-rebaseline-tests.md -DryRun
   ```

   Exit `0`; output có `worker-codex`, endpoint kết thúc `/v1`, provider
   `ninerouter`, wire API `responses` và network sandbox `false`; không chứa key.

4. Khi chạy từ phiên Codex, Claude dry-run phải bị launcher từ chối trước khi gọi
   model, với thông báo engine `claude` không được phép từ host `codex`.

5. `rg -n "api-combo|ANTHROPIC_BASE_URL|ANTHROPIC_MODEL" docs/agents/orchestrator.md`
   không còn kết quả. Tài liệu có cả `worker-claude` và `worker-codex`.

6. `git diff --check -- scripts/agents/run-worker.ps1 docs/agents/orchestrator.md`
   không báo whitespace error.

7. Worker ghi `docs/plan/REPORT-worker-launcher-two-aliases.md` gồm file đã đổi,
   output tóm tắt của từng acceptance và mọi blocker. Nếu tạo commit local, chỉ
   stage các file thuộc task này; không dùng `git add -A`, không push/gh.

## Feedback vòng 1

_Để trống — orchestrator điền sau khi chấm nếu trượt._
