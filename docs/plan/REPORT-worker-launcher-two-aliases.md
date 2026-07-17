# Báo cáo worker launcher hai alias

## Kết quả thực hiện

- Thêm `scripts/agents/run-worker.ps1` với hai engine `claude` và `codex`, cấu hình
  9router trung lập, kiểm tra plan nằm trong repo, prompt plan/report chuẩn và chế độ
  `-DryRun` không cần key.
- Adapter Claude ánh xạ endpoint gốc, key và cùng alias `worker-claude` cho model
  chính lẫn small/fast; prompt đứng trước danh sách `--disallowedTools` chặn push/`gh`.
- Adapter Codex dùng provider `ninerouter`, endpoint `/v1`, wire API `responses`,
  workspace-write không network và loại các biến credential khỏi subprocess shell.
- Cập nhật `docs/agents/orchestrator.md` để mô tả hai alias chung pool/failover nhưng
  khác wire protocol, dùng launcher ở mỗi vòng và giữ nguyên engine/alias khi có lỗi.

## File đã thay đổi

- `scripts/agents/run-worker.ps1`
- `docs/agents/orchestrator.md`
- `docs/plan/REPORT-worker-launcher-two-aliases.md`

## Acceptance

1. PowerShell parser: exit `0`, output `PowerShell parse: PASS`.
2. Claude dry-run: exit `0`; output có `worker-claude`, endpoint gốc
   `http://192.168.21.30:20128`, plan `a1-rebaseline-tests.md`, cùng alias cho main và
   small/fast; không có `/v1` ở endpoint và không in giá trị key.
3. Codex dry-run: exit `0`; output có `worker-codex`, endpoint
   `http://192.168.21.30:20128/v1`, provider `ninerouter`, `wire_api: responses` và
   `sandbox_workspace_write.network_access: false`; không in giá trị key.
4. Quét tài liệu: `rg` cho các tham chiếu cấu hình cũ trả exit `1` vì không có kết
   quả; quét hai alias trả exit `0` và tìm thấy cả `worker-claude`, `worker-codex`.
5. `git diff --check -- scripts/agents/run-worker.ps1 docs/agents/orchestrator.md`:
   exit `0`, không có whitespace error.
6. Report này đã được tạo; không có commit, stage, push hay lệnh `gh` nào được thực hiện.

## Kiểm tra bổ sung

- Gắn key giả rồi kiểm tra output của cả hai dry-run: exit `0`, không rò giá trị key.
- Truyền một plan tồn tại ngoài repo: launcher từ chối với exit `1` như mong đợi.

## Blocker

Không có.

## Theo dõi khóa host (2026-07-17)

- Launcher hiện tự nhận diện host điều phối: Codex (`CODEX_THREAD_ID`) chỉ được gọi
  `-Engine codex` / `worker-codex`; Claude Code (`CLAUDECODE` hoặc
  `CLAUDE_CODE_ENTRYPOINT`) chỉ được gọi `-Engine claude` / `worker-claude`.
  Ngoài phiên agent, automation phải truyền `-OrchestratorHost` khớp engine.
- Đã kiểm tra: PowerShell parser pass; Codex dry-run hiện `orchestrator_host: codex`
  và `worker-codex`; gọi `-Engine claude` từ phiên Codex bị từ chối với exit code 1
  trước khi gọi model.
- Sửa adapter Codex để truyền `shell_environment_policy.exclude` dưới dạng TOML
  array đúng kiểu trên Windows. Cấu hình không còn lỗi parse string/sequence.
- Lần dispatch A1 bằng Codex đi tới `POST /v1/responses` rồi bị 9router từ chối:
  `404 No active credentials for provider: openai`. Chẩn đoán sau đó cho thấy đây
  là fallback khi alias `worker-codex` không tồn tại, không phải lỗi credential
  client. Cùng endpoint trả `200` cho `api-combo`, nhưng body là schema Chat
  Completions thay vì Responses; đây vẫn là blocker tương thích Codex. Không đổi
  engine, alias hoặc dùng model có tiền tố provider để vượt qua.
