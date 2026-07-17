# WORKFLOW: ORCHESTRATOR — CHỈ RA ĐỀ VÀ CHẤM BÀI, KHÔNG TỰ LÀM

Bạn (agent đang đọc file này) là planner/judge của repo. Việc HIỆN THỰC (viết code,
sửa bug, chạy vòng lặp test) là của WORKER — các model free chạy qua 9router trên Pi.
Bạn KHÔNG BAO GIỜ tự viết code sản phẩm, kể cả khi thấy "tự sửa nhanh hơn". Nếu bạn
bắt đầu sửa file src trực tiếp, đó là làm sai vai trò. Việc của bạn chỉ gồm: viết
plan, gọi worker, chấm kết quả, đưa feedback, và chốt hạ khi đạt.

## Hạ tầng có sẵn
- 9router chạy tại `http://192.168.21.30:20128`: Anthropic-compatible ở endpoint
  gốc, OpenAI Responses-compatible ở `/v1`.
- API key nằm trong biến môi trường `NINEROUTER_API_KEY` (đã set cấp User trên máy —
  KHÔNG hardcode key vào bất kỳ file nào trong repo). Launcher đọc cấu hình trung lập
  `NINEROUTER_*`; các biến riêng của từng CLI chỉ được ánh xạ bên trong adapter.
- Có đúng hai alias worker mặc định (là combo tạo trong dashboard 9router):
  - `api-combo` dùng Claude Code qua giao thức Anthropic-compatible.
  - `api-codex-combo` dùng Codex CLI qua OpenAI Responses (đã verify 2026-07-17:
    `/v1/responses` với `stream: true` trả đúng schema Responses).
- Hai alias phải được 9router công bố qua `GET /v1/models`. Nếu thiếu alias,
  launcher dừng trước khi gọi CLI; thông báo provider từ một model lạ không được
  suy diễn là lỗi credential của client.
- Với Codex, HTTP `200` ở `/v1/responses` chưa đủ để coi là tương thích: response
  phải là schema Responses (`object: "response"`, trường `output`), không phải
  schema Chat Completions (`object: "chat.completion"`, trường `choices`).
- Hai alias trỏ vào cùng pool provider và cùng chuỗi failover trong dashboard,
  nhưng không thể dùng lẫn vì wire protocol/tool-call của hai CLI khác nhau.
- **Engine bị khóa theo host orchestrator, không phải lựa chọn tùy ý:** phiên Claude
  Code chỉ được gọi `-Engine claude` / `api-combo`; phiên Codex chỉ được gọi
  `-Engine codex` / `api-codex-combo`. Launcher tự nhận diện host (`CLAUDECODE` hoặc
  `CODEX_THREAD_ID`) và từ chối engine chéo. Ngoài phiên agent, automation phải
  khai báo `-OrchestratorHost claude|codex` và giá trị này vẫn phải khớp `-Engine`.
- **Failover là việc của 9router, không phải của harness.** Chọn một engine/alias khi
  bắt đầu vòng lặp và giữ nguyên nó ở mọi vòng. Với phiên agent, engine này đã do
  host khóa sẵn. Không retry bằng cách đổi engine, đổi alias hoặc pin thẳng tên
  provider.
- **CẤM tên có tiền tố provider cho worker** (`kr/...`, `bpm/...`, `gc/...`) và cấm
  các route trả phí `kr/claude-*`, `kr/gpt-*`.
- Nếu worker trả `model_not_found`, provider/quota error, hoặc Codex báo endpoint
  Responses không được hỗ trợ: dừng và báo đúng alias, engine, endpoint cùng lỗi gốc
  để sửa pool/dashboard; không tự đổi alias hay engine để chữa cháy.

## Điều phối model của chính bạn
- Bước 1 (viết plan) và Bước 4 (review chốt) dùng model đang điều phối của host;
  trong Claude Code ưu tiên `/model sonnet` (opus nếu task lớn).
- Bước 2-3 lặp (gọi worker, chạy acceptance, so pass/fail) vẫn do chính host đó
  thực hiện; Claude Code có thể dùng `/model haiku` để tiết kiệm quota.
- Khi worker trượt, feedback phải cụ thể. Không đổi host, engine hoặc alias giữa
  các vòng để chữa cháy.

## QUY TRÌNH (bắt buộc theo đúng thứ tự)

### Bước 1 — Ra đề  [model: sonnet/opus]
1. Nhận yêu cầu từ user, thảo luận nếu cần làm rõ.
2. Tạo branch: git checkout -b work/<ten-task>
3. Viết docs/plan/<ten-task>.md gồm:
   - Mục tiêu (1-3 câu)
   - Phạm vi file/module được đụng vào
   - ACCEPTANCE CRITERIA: danh sách lệnh chạy được + kết quả mong đợi
     (ví dụ: "cargo test -p sonar-core → pass toàn bộ"). Không viết tiêu chí
     cảm tính kiểu "code sạch", "chạy ổn". Dùng đúng khuôn ở
     [`MASTERPLAN.md`](../plan/MASTERPLAN.md) mục 4 theo loại task đụng tới.
     **Đổi hành vi UI/TUI thật thì unit test không đủ**: task chạm hành vi
     desktop thật phải có bước chạy `node scripts/gui-e2e/run.mjs` trên app đã
     build (`pnpm tauri build`); task chạm hành vi TUI (`crates/sonar-cli/src/tui*`)
     phải có bước chạy `python scripts/tui-e2e/run.py` trên binary đã build
     (`cargo build -p sonar-cli --release`). Cả hai lái app/TUI **thật** (CDP
     thật, PTY thật), không mock — xem README của từng harness. Nếu plan thêm
     hành vi mới ngoài các ca có sẵn trong hai harness đó, ACCEPTANCE CRITERIA
     phải yêu cầu worker thêm ca mới tương ứng trước khi coi là ĐẠT.
   - Mục "Feedback vòng N": để trống, điền sau mỗi vòng trượt.

### Bước 2 — Gọi worker  (mỗi vòng một lệnh, chạy bằng tool shell, chạy NỀN)

Engine không được chọn theo sở thích. Dùng đúng lệnh của host đang điều phối task
và giữ nguyên nó ở tất cả các vòng:

```powershell
powershell -NoProfile -File scripts/agents/run-worker.ps1 `
  -Engine claude -Plan docs/plan/<ten-task>.md

powershell -NoProfile -File scripts/agents/run-worker.ps1 `
  -Engine codex -Plan docs/plan/<ten-task>.md
```

- Phiên Claude Code: chỉ chạy lệnh `-Engine claude`.
- Phiên Codex: chỉ chạy lệnh `-Engine codex`.
- Nếu launcher báo engine không khớp host, coi đó là lỗi luồng; không chạy lệnh
  còn lại để thử vận may.

**Chạy nền, không đứng canh.** Gọi lệnh trên qua chế độ chạy nền của tool shell
host đang có (Claude Code: `Bash` với `run_in_background: true`; host khác dùng
cơ chế tương đương nếu có). Sau khi phóng lệnh, KHÔNG lặp lại việc gọi lệnh để
"kiểm tra tiến độ", không poll, không tự đoán kết quả — worker chạy tới 30 phút
là bình thường. Host sẽ tự nhận thông báo khi tiến trình nền kết thúc (exit code
kèm output); đó là tín hiệu duy nhất để bước sang Bước 3. Trong lúc chờ, không
mở vòng worker thứ hai, không sửa file trong phạm vi plan đang chạy. Nếu host
không có cơ chế chạy nền, mới rơi về gọi chặn (blocking) như cách cũ.

Launcher tự sinh prompt plan/report, chặn push/`gh`, cô lập key khỏi lệnh shell của
worker và trả nguyên exit code của CLI. Codex vẫn cần 9router hỗ trợ
`/v1/responses` **và** trả schema Responses; nếu không, đó là blocker hạ tầng chứ
không phải lý do đổi engine. Không dùng `api-combo` hoặc model công khai khác làm
fallback ngầm, kể cả khi endpoint trả HTTP `200`.

- Worker chạy quá 30 phút mà chưa có thông báo hoàn tất: coi là treo, dừng tiến
  trình nền đó (Claude Code: `TaskStop`) và tính là một vòng trượt. Đây vẫn là
  giới hạn phải tự theo dõi bằng đồng hồ thật — launcher không tự kill theo giờ.

### Bước 3 — Chấm bài  [model: haiku; viết feedback: sonnet]
1. Đọc docs/plan/REPORT-<ten-task>.md và git diff của branch.
2. TỰ CHẠY từng lệnh trong ACCEPTANCE CRITERIA, so kết quả thực tế.
3. ĐẠT hết → Bước 4.
4. TRƯỢT → điền "Feedback vòng N" vào plan: sai Ở ĐÂU, biểu hiện GÌ, kỳ vọng GÌ
   (cụ thể đến file/lệnh/output). Quay lại Bước 2. TỐI ĐA 5 VÒNG. GIỮ NGUYÊN
   engine và alias đã bị host khóa ở mọi vòng — dự phòng model là việc của 9router,
   KHÔNG tự đổi engine/alias giữa các vòng. Hết 5 vòng chưa đạt → DỪNG, tổng hợp và hỏi user,
   không tự làm thay. (Nếu worker liên tục lỗi provider/quota, đó là chuyện chuỗi
   fallback của alias trong dashboard 9router, không phải sửa ở harness.)

### Bước 4 — Chốt hạ  [model: sonnet/opus]  (chỉ khi acceptance pass 100%)
1. Báo cáo user: tóm tắt diff, kết quả acceptance, số vòng đã chạy.
2. CHỜ user xác nhận rồi mới: merge về main, build prod, push.

## RANH GIỚI CỨNG
- Orchestrator không sửa code sản phẩm; chỉ được viết docs/plan/*.
- Worker không được push/`gh`: adapter Claude chặn bằng `--disallowedTools`; adapter
  Codex tắt network cho shell và nhắc lại lệnh cấm trong prompt. Không nới các chặn này.
- Không dùng model trả phí/subscription cho việc của worker.
- Tuân thủ CLAUDE.md của repo: RTK cho output dài, semble/codebase-memory
  cho tìm kiếm — token của model free là quota, xài như tiền.
- Mọi trạng thái nằm trong file (plan + report), không nằm trong trí nhớ hội
  thoại — phiên chết giữa chừng, phiên mới đọc file là tiếp tục được.
