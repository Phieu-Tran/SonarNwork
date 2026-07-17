# REPORT — B1 — Xác minh installer Windows (Vòng 3)

## Tình trạng

- Kết quả: **ĐẠT**
- Thay đổi code: Đã xoá `$installRoot = $null` (dòng 11 cũ) trong `scripts/install.ps1`.
- Tổng thay đổi code (cộng dồn vòng 2+3): 3 dòng trong `scripts/install.ps1`:
  - Dòng 89: `\\s{2}` → `\s{2}` (regex escape fix)
  - Dòng 95: `\\s+` → `\s+` (regex escape fix)
  - Dòng 11: `$installRoot = $null` → *(xoá)* (parameter shadowing fix)

## Kết quả các bước

| Bước | Kết quả | Ghi chú |
|---|---|---|
| `cargo build -p sonar-cli --release` | Exit 0 | Compiled thành công |
| `pnpm tauri build` | Exit 0 | 2 bundles produced |
| 3 binaries tồn tại | ✅ | sonar.exe, sonarnwork.exe, sonarnwork-app.exe |
| `install.ps1 -InstallRoot "$env:TEMP\sonarnwork-b1-verify"` | Exit 0 | Tải v0.1.3, verify checksum, cài thành công |
| `sonar.exe --version` | Exit 0 | Output: `sonar 0.1.3` |
| `sonar.exe open ui` | Exit 0 | GUI khởi động (process chạy nền, đã kill để cleanup) |
| Cleanup PATH | ✅ | Đã xoá entry `sonarnwork-b1-verify` khỏi User PATH |
| Cleanup install dir | ✅ | Đã xoá `$env:TEMP\sonarnwork-b1-verify` |
| PATH before == PATH after | ✅ | `b1-path-before.txt` == `b1-path-after.txt` |

## Chi tiết release

- Phiên bản: **v0.1.3** (`Phieu-Tran/SonarNwork`)
- InstallRoot dùng: `$env:TEMP\sonarnwork-b1-verify`
- Checksum verification: SHA-256 khớp (`SHA256SUMS.txt` từ release)

## Bằng chứng

- `docs/plan/evidence/b1-path-before.txt` — User PATH trước khi chạy installer
- `docs/plan/evidence/b1-path-after.txt` — User PATH sau khi cleanup
- Diff result: **giống hệt nhau** (không có thay đổi rác)

## Root cause analysis

Ba bugs đã tìm thấy và sửa trong `scripts/install.ps1`:

1. **Regex escape (vòng 1-2)**: PowerShell double-quoted strings dùng backtick `` ` `` làm escape, không phải backslash `\`. `\\s{2}` được interpret là literal `\s{2}` thay vì regex `\s{2}` (hai khoảng trắng). Fix: dùng `\s{2}` và `\s+`.

2. **Parameter shadowing (vòng 3)**: Dòng `$installRoot = $null` ghi đè tham số `-InstallRoot` vì PowerShell không phân biệt hoa/thường tên biến. Người dùng truyền `-InstallRoot` nào cũng bị reset thành `$null`, khiến script luôn cài vào `%LOCALAPPDATA%\Programs\SonarNwork`. Fix: xoá dòng đó — `$InstallRoot` đã có default `$null` từ `param()`.

## Git status

`git status --short`: chỉ có `scripts/install.ps1` modified + evidence files + report.
Không có thay đổi code sản phẩm ngoài `scripts/install.ps1`. Không commit, không push.
