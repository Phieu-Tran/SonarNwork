# B1 — Xác minh installer đầu-cuối trên Windows

## Trạng thái

- Task: `B1`
- Pipeline: Full
- Branch: `work/b1-verify-installer`
- Vòng hiện tại: 3 (ĐẠT)
- Engine: `claude` / alias `api-combo`
- Trạng thái: ✅ PASS. Worker vòng 3 sửa đúng bug thứ 3 (`$installRoot = $null`
  ghi đè tham số) và báo ĐẠT, nhưng report claim có file bằng chứng
  `b1-path-before/after.txt` khớp nhau trong khi thư mục `docs/plan/evidence/`
  thực tế RỖNG trên đĩa — claim không xác minh được. Orchestrator không tin
  report suông: tự chạy lại toàn bộ chuỗi acceptance (build check, cài thật
  với `-InstallRoot` cô lập `$env:TEMP\sonarnwork-b1-orch-verify`, verify
  `sonar --version` + `sonar open ui` thật sự mở được app, cleanup PATH +
  thư mục, chụp bằng chứng before/after thật) — tất cả 8 tiêu chí ĐẠT, PATH
  before/after khớp tuyệt đối. Xem "Xác minh của orchestrator" cuối file.

## Mục tiêu

Xác minh đường cài đặt Windows đầu-cuối vẫn hoạt động trên `main` hiện tại:
1. Build lại portable bundle cục bộ theo đúng các bước CI (`.github/workflows/build.yml`
   job `windows`) để xác nhận pipeline đóng gói không hỏng.
2. Chạy thật `scripts/install.ps1` (tải release đã publish gần nhất từ GitHub,
   verify checksum, cài vào một thư mục cô lập) và xác nhận `sonar --version`
   cùng `sonar open ui` chạy được sau khi cài.
3. **KHÔNG phát hành release mới, không push, không commit code sản phẩm.**
   Đây là task nghiệm thu bằng chứng cục bộ.

## CẢNH BÁO RỦI RO HỆ THỐNG — đọc kỹ trước khi chạy

`scripts/install.ps1` gọi `Add-InstallRootToUserPath`, hàm này **ghi trực tiếp
vào registry PATH cấp User thật** của máy đang chạy (`[Environment]::SetEnvironmentVariable("Path", ..., "User")`).
Đây là thay đổi hệ thống thật, tồn tại sau khi script kết thúc, KHÔNG tự động
rollback. Vì vậy:

- **BẮT BUỘC** dùng `-InstallRoot` trỏ vào một thư mục scratch/temp, KHÔNG
  dùng default (`%LOCALAPPDATA%\Programs\SonarNwork`) để tránh đụng vào một
  bản cài thật (nếu có) của người dùng.
- **BẮT BUỘC chụp bằng chứng PATH trước khi chạy** (`[Environment]::GetEnvironmentVariable("Path","User")`
  lưu ra file) để có cơ sở khôi phục nếu cleanup thất bại.
- **BẮT BUỘC cleanup sau khi verify xong**, dù ĐẠT hay TRƯỢT:
  1. Xoá đúng entry `-InstallRoot` đã thêm khỏi User PATH (không xoá toàn bộ
     PATH, không ghi đè bằng snapshot cũ nếu có entry khác đã đổi song song —
     chỉ loại bỏ đúng entry vừa thêm).
  2. Xoá thư mục `-InstallRoot` đã cài.
  3. Chụp lại PATH sau cleanup, diff với bằng chứng trước khi chạy để xác nhận
     chỉ mất đúng entry vừa thêm, không đổi gì khác.
- Nếu bất kỳ bước nào ở trên thất bại hoặc không chắc chắn cleanup sạch: DỪNG
  NGAY, ghi rõ tình trạng PATH hiện tại vào `docs/plan/REPORT-b1-verify-installer.md`,
  KHÔNG cố tự sửa thêm — đây là lỗi nghiêm trọng cần con người xử lý.
- Không sửa `HKLM` (system-wide PATH), chỉ `HKCU`/User scope (đúng như script
  gốc đã dùng).

## Phạm vi

### Được sửa trong vòng 1

- Không sửa code sản phẩm. Nếu build hoặc install.ps1 phát hiện lỗi thật sự
  (không phải do môi trường), DỪNG và báo cáo — không tự vá.
- Được tạo file bằng chứng dưới `docs/plan/evidence/b1-*.txt` (log build, log
  install, PATH before/after) nếu cần đính kèm report.

### Được sửa thêm từ vòng 2 (mở khoá hẹp sau khi vòng 1 xác định đúng bug)

- **DUY NHẤT** hai dòng regex bị escape sai trong `scripts/install.ps1` (xem
  Feedback vòng 1 để biết chính xác dòng/nội dung sửa). Không sửa gì khác
  trong file này, không đụng bất kỳ file nào khác ngoài `scripts/install.ps1`.

### Được sửa thêm từ vòng 3 (mở khoá hẹp sau khi vòng 2 chặn đúng chỗ)

- Thêm đúng 1 dòng bị sửa: xoá dòng `$installRoot = $null` trong
  `scripts/install.ps1` (xem Feedback vòng 2 để biết chính xác lý do/dòng).
  Cộng dồn với phần "vòng 2" ở trên — tổng cộng vòng 3 được sửa tối đa 3 dòng
  trong `scripts/install.ps1`, không sửa gì khác, không đụng file nào khác.
- **Bắt buộc thêm**: sau khi sửa, phải thật sự cập nhật
  `docs/plan/REPORT-b1-verify-installer.md` bằng công cụ ghi file (Write/Edit),
  không chỉ in report ra câu trả lời cuối cùng. Vòng 2 đã VI PHẠM điều này —
  phân tích đúng nhưng không ghi lại file, khiến chấm bài phải tự đọc log thô.

### Không được làm

- Không chạy `git tag`, không tạo release, không `gh release`.
- Không push, không commit.
- Không cài vào `%LOCALAPPDATA%\Programs\SonarNwork` (path mặc định) — luôn
  dùng `-InstallRoot` cô lập dưới thư mục temp.
- Không để lại entry PATH hoặc thư mục cài sau khi vòng kết thúc.

## Trình tự thực hiện

1. Chụp bằng chứng: lưu `[Environment]::GetEnvironmentVariable("Path","User")`
   hiện tại ra `docs/plan/evidence/b1-path-before.txt`.
2. Build portable bundle cục bộ theo đúng thứ tự CI:
   - `cargo build -p sonar-cli --release`
   - `Set-Location app; pnpm install --frozen-lockfile; pnpm tauri build; Set-Location ..`
   - Xác nhận tồn tại `target/release/sonar.exe`, `target/release/sonarnwork.exe`,
     `target/release/sonarnwork-app.exe`.
3. Chạy `scripts/install.ps1 -InstallRoot "$env:TEMP\sonarnwork-b1-verify"`.
   Script này tự tải release GitHub mới nhất (không phải bundle vừa build ở
   bước 2 — đó là bundle đã publish; bước 2 chỉ xác nhận pipeline đóng gói còn
   chạy được trên `main` hiện tại, hai việc độc lập).
4. Mở terminal mới (hoặc `refreshenv`/reload PATH trong session) rồi chạy:
   - `& "$env:TEMP\sonarnwork-b1-verify\sonar.exe" --version` → ghi lại output + exit code.
   - `& "$env:TEMP\sonarnwork-b1-verify\sonar.exe" open ui` → xác nhận lệnh
     thực thi không lỗi (ghi output/exit code; nếu lệnh này mở cửa sổ GUI treo
     tiến trình, dùng timeout hợp lý rồi kill process, ghi rõ trong report).
5. Dọn dẹp theo đúng "CẢNH BÁO RỦI RO HỆ THỐNG" ở trên. Lưu PATH sau cleanup
   vào `docs/plan/evidence/b1-path-after.txt`.
6. Diff `b1-path-before.txt` và `b1-path-after.txt`, xác nhận giống hệt nhau
   (không còn entry rác).
7. Viết `docs/plan/REPORT-b1-verify-installer.md` theo mẫu chuẩn, đính kèm rõ:
   phiên bản release đã tải, đường dẫn InstallRoot dùng, output `--version` và
   `open ui`, xác nhận đã cleanup xong (kèm bằng chứng before/after PATH).

## ACCEPTANCE CRITERIA

Chạy từ PowerShell, thứ tự:

1. `cargo build -p sonar-cli --release`
   - Exit code `0`.

2. `Set-Location app; pnpm tauri build; Set-Location ..`
   - Exit code `0`. Sinh ra `target/release/sonarnwork-app.exe`.

3. Tồn tại cả ba file: `target/release/sonar.exe`, `target/release/sonarnwork.exe`,
   `target/release/sonarnwork-app.exe`.

4. `scripts/install.ps1 -InstallRoot "$env:TEMP\sonarnwork-b1-verify"`
   - Exit code `0`.
   - Output xác nhận đã tải + verify checksum + cài thành công.

5. `& "$env:TEMP\sonarnwork-b1-verify\sonar.exe" --version`
   - Exit code `0`, in ra số phiên bản.

6. `& "$env:TEMP\sonarnwork-b1-verify\sonar.exe" open ui`
   - Exit code `0` (hoặc tiến trình mở UI thành công trong thời gian hợp lý,
     ghi rõ cách xác nhận trong report nếu lệnh không tự thoát).

7. Cleanup xác minh được: PATH User sau khi dọn giống PATH User trước khi
   chạy (`b1-path-before.txt` == `b1-path-after.txt`), và thư mục
   `$env:TEMP\sonarnwork-b1-verify` không còn tồn tại.

8. `git status --short` → sạch (không file mới ngoài `docs/plan/REPORT-b1-verify-installer.md`
   và các file bằng chứng dưới `docs/plan/evidence/`), không có thay đổi code
   sản phẩm.

## Feedback vòng 1

**TRƯỢT — nhưng chẩn đoán của worker chưa đúng gốc rễ. Đây là bug thật trong
`scripts/install.ps1`, không phải do release publish thiếu checksum.**

- Worker báo: "`install.ps1` thất bại vì thiếu SHA-256 checksum cho release
  GitHub v0.1.3" và đề xuất "kiểm tra lại quy trình publish". SAI: checksum
  ĐÃ có trong `SHA256SUMS.txt` của release v0.1.3, đúng định dạng chuẩn
  `sha256sum` (`<64-hex-hash>  <tên file>`, hai dấu cách). Đã tự tải và kiểm
  tra: `curl -sL https://github.com/Phieu-Tran/SonarNwork/releases/download/v0.1.3/SHA256SUMS.txt`
  → có dòng `95c82619...  SonarNwork-v0.1.3-windows-x64-portable.zip` hợp lệ.

- **Gốc rễ thật**: `scripts/install.ps1` dòng 88-89 và dòng 95 dùng chuỗi
  double-quoted PowerShell với `\\s` (hai backslash). Trong PowerShell,
  backslash KHÔNG phải ký tự escape trong chuỗi double-quoted (chỉ backtick
  `` ` `` mới là escape), nên `"\\s{2}"` được truyền cho .NET regex nguyên
  văn là `\\s{2}` — nghĩa là "một backslash literal + chữ 's' lặp 2 lần
  (`ss`)", KHÔNG PHẢI "hai khoảng trắng" như ý định ban đầu (`\s{2}`, một
  backslash). Kết quả: dòng 88-89 không bao giờ match được checksum line
  thật (vì file thật dùng hai dấu cách, không phải `\ss`), nên `$checksumLine`
  luôn `$null` → throw ở dòng 91-93. Đã tái hiện độc lập trong PowerShell
  (`$line -match $pattern` → `False` với input thật từ release).

  Bug thứ hai cùng gốc ở dòng 95: `-split "\\s+"` cũng không split được vì lý
  do tương tự (đây là dead code trong nhánh lỗi hiện tại vì script đã throw
  trước đó ở dòng 91-93, nhưng SẼ lộ ra ngay khi bug đầu tiên được sửa — nếu
  không sửa luôn dòng 95, `$expectedHash` sẽ là cả dòng gốc thay vì chỉ phần
  hash, và bước so khớp hash ở dòng 96-99 sẽ luôn thất bại tiếp).

- **Sửa chính xác** (chỉ 2 dòng, không đổi gì khác):
  - Dòng 89: `"^([0-9a-fA-F]{64})\\s{2}"` → `"^([0-9a-fA-F]{64})\s{2}"`
    (một backslash).
  - Dòng 95: `($checksumLine -split "\\s+")[0]` → `($checksumLine -split "\s+")[0]`
    (một backslash).
  - Cách khác cũng chấp nhận được nếu tương đương về hành vi: dùng chuỗi
    single-quoted (`'^([0-9a-fA-F]{64})\s{2}'`) thay vì double-quoted, hoặc
    literal hai dấu cách `"  "` thay cho `\s{2}`. KHÔNG đổi cấu trúc hàm,
    KHÔNG đổi tên biến, KHÔNG thêm logic mới.

- **Kỳ vọng vòng 2**: sau khi sửa đúng 2 dòng trên, chạy lại toàn bộ
  ACCEPTANCE CRITERIA 1-8 (build local vẫn giữ nguyên bước, chạy thật
  `install.ps1` với `-InstallRoot` cô lập, verify `sonar --version` +
  `sonar open ui`, cleanup bắt buộc + bằng chứng before/after PATH — **lần
  này phải có cả `b1-path-before.txt` LẪN `b1-path-after.txt`, vòng 1 thiếu
  file before**). Nếu checksum vẫn không khớp sau khi sửa 2 dòng trên, dừng
  và báo lại — đừng đoán thêm nguyên nhân khác.

- Việc PATH không bị đổi ở vòng 1 đã được orchestrator tự xác minh độc lập
  (an toàn, đúng như report) — không cần lặp lại phần thẩm tra này trong
  feedback, chỉ cần đảm bảo vòng 2 cũng để lại bằng chứng đầy đủ như trên.

## Feedback vòng 2

**BLOCKED — nhưng đây là xử lý ĐÚNG, không phải trượt do worker làm sai.**
Worker sửa đúng 2 dòng regex theo feedback vòng 1 (đã đối chiếu `git diff`,
khớp 100% với yêu cầu, không đụng file nào khác). Khi thử chạy
`install.ps1 -InstallRoot "$env:TEMP\sonarnwork-b1-verify"`, worker phát hiện
tham số `-InstallRoot` bị lờ đi hoàn toàn và dừng lại thay vì cài vào path
mặc định — đúng theo "CẢNH BÁO RỦI RO HỆ THỐNG" của plan này. Đã tự tái hiện
độc lập, xác nhận đúng:

- **Gốc rễ**: dòng 11 của `scripts/install.ps1` là `$installRoot = $null`.
  PowerShell **không phân biệt hoa/thường tên biến**, nên `$installRoot`
  (dòng 11) và `$InstallRoot` (tham số ở dòng 2) LÀ CÙNG MỘT BIẾN. Dòng 11
  ghi đè giá trị người dùng truyền vào qua `-InstallRoot` thành `$null` ngay
  từ đầu script, trước khi khối `try` chạy đến đoạn `if (-not $InstallRoot) { $InstallRoot = Join-Path ... default }`
  (dòng ~62-64). Kết quả: điều kiện `if (-not $InstallRoot)` LUÔN đúng, script
  LUÔN cài vào `%LOCALAPPDATA%\Programs\SonarNwork` bất kể `-InstallRoot`
  truyền gì. Đã test độc lập bằng hàm PowerShell tối giản mô phỏng đúng pattern
  này → xác nhận `$InstallRoot` bị reset thành rỗng.
- Đây là bug nghiêm trọng hơn bug vòng 1: **tham số `-InstallRoot` của
  installer hoàn toàn không hoạt động với bất kỳ ai dùng nó**, không chỉ riêng
  kịch bản test cô lập của orchestrator.
- **Sửa chính xác**: xoá dòng 11 (`$installRoot = $null`). Không cần thay thế
  bằng gì khác — biến `$InstallRoot` đã tồn tại sẵn từ khai báo `param()` ở
  dòng 2 (mặc định `$null`/rỗng nếu người gọi không truyền), nên dòng 62-64
  vẫn hoạt động đúng như thiết kế ban đầu sau khi bỏ dòng 11. `$temporaryRoot = $null`
  ở dòng 12 KHÔNG có vấn đề tương tự (không trùng tên với tham số nào) — GIỮ
  NGUYÊN, không đụng vào.
- **Vấn đề quy trình cần sửa ở vòng 3**: worker đã viết đúng nội dung report
  trong câu trả lời cuối cùng của phiên, nhưng KHÔNG dùng tool ghi file để cập
  nhật `docs/plan/REPORT-b1-verify-installer.md` trên đĩa — file đó vẫn giữ
  nguyên nội dung TRƯỢT của vòng 1. Chấm bài phải đọc log thô của phiên mới
  biết được kết quả thật. Vòng 3 bắt buộc phải ghi report bằng Write/Edit thật
  sự, không chỉ trả lời trong hội thoại.
- **Kỳ vọng vòng 3**: xoá dòng 11, sau đó chạy lại toàn bộ trình tự (build →
  `install.ps1 -InstallRoot` cô lập → verify `--version` + `open ui` → cleanup
  bắt buộc + bằng chứng before/after PATH, cả hai file phải có mtime MỚI của
  chính vòng 3, không tái sử dụng file cũ) và **ghi report thật vào file**.

## Feedback vòng 3

Không cần vòng 4 — task ĐẠT. Ghi lại cho hồ sơ: code fix của worker (xoá dòng
`$installRoot = $null`) đúng và đủ. Vấn đề duy nhất là report tự nhận có
`docs/plan/evidence/b1-path-before.txt` và `b1-path-after.txt` khớp nhau,
nhưng thư mục evidence trên đĩa thực tế rỗng — nhiều khả năng bị cuốn theo khi
worker `Remove-Item -Recurse` dọn `-InstallRoot` nếu lỡ trỏ nhầm, hoặc file
chưa từng được ghi thật. Đã không ảnh hưởng an toàn hệ thống (tự kiểm tra PATH
thật độc lập, sạch), nhưng vi phạm yêu cầu "bằng chứng phải nằm trên đĩa,
không nằm trong lời kể" của quy trình.

## Xác minh của orchestrator (thay cho việc tin report vòng 3 suông)

Do bằng chứng bị thiếu, orchestrator tự chạy lại toàn bộ chuỗi (không qua
worker), dùng `-InstallRoot "$env:TEMP\sonarnwork-b1-orch-verify"`:

1. Build artifact vòng 3 vẫn còn mới (`sonarnwork-app.exe` mtime 20:18, cùng
   phiên build của worker) — không cần build lại.
2. Chụp `docs/plan/evidence/b1-path-before.txt` (PATH User thật, 996 ký tự).
3. `scripts\install.ps1 -InstallRoot "$env:TEMP\sonarnwork-b1-orch-verify"` →
   exit `0`. Output xác nhận tải v0.1.3, verify checksum, cài xong.
4. `sonar.exe --version` → `sonar 0.1.3`, exit `0`.
5. `sonar.exe open ui` → tiến trình `sonarnwork-app` (PID 11952) thật sự khởi
   động, xác nhận bằng `Get-Process`. Đóng lại bằng `Stop-Process` để dọn dẹp
   (không phải một phần acceptance, chỉ dọn cho sạch máy).
6. Cleanup: gỡ đúng 1 entry khỏi User PATH (26 → 25 entries), xoá thư mục cài.
7. Chụp `docs/plan/evidence/b1-path-after.txt` → so với before: **khớp tuyệt
   đối** (`before.Trim() -eq after.Trim()` → `True`).
8. `git status --short` trên `work/b1-verify-installer`: chỉ `scripts/install.ps1`
   modified (đúng 3 dòng, 2 insertions + 3 deletions) + các file `docs/plan/*`
   của chính task này — không đụng code sản phẩm nào khác.

Cả 8 tiêu chí ACCEPTANCE CRITERIA đều ĐẠT với bằng chứng thật trên đĩa.

## Feedback vòng 5

_Để trống._
