# REPORT B2 — Xác minh đường `sonar update`

## Thông tin chung

- **Task:** B2
- **Branch:** `work/b2-verify-self-update`
- **Engine:** `api-combo` (Claude)
- **Pipeline:** Compact
- **Thời gian:** 2026-07-17

## Kết quả thực hiện

### 1. Xác nhận version (bước 1)

```json
{
  "tag_name": "v0.1.3",
  "published_at": "2026-07-15T14:52:22Z"
}
```

| Nguồn | Version |
|---|---|
| `Cargo.toml` (workspace) | `0.1.3` |
| GitHub release mới nhất (`tag_name`) | `v0.1.3` |
| Kết luận | ✅ **Khớp** — `ordering = Equal`, an toàn chạy `sonar update` thật |

### 2. Unit test mới thêm

**File sửa đổi duy nhất:** `crates/sonar-cli/src/update.rs` (chỉ thêm vào `#[cfg(test)] mod tests`)

#### Test `update_channel` (5 cases)

| Test | Path input | Expected | Kết quả |
|---|---|---|---|
| `update_channel_scoop` | `C:\Users\test\scoop\apps\sonarnwork\current\sonar.exe` | `Scoop` | ✅ Pass |
| `update_channel_winget` | `C:\Users\test\AppData\Local\Microsoft\WinGet\Packages\phieutran.sonarnwork_1.0.0_x64__abc\sonar.exe` | `Winget` | ✅ Pass |
| `update_channel_cargo` | `C:\Users\test\.cargo\bin\sonar.exe` | `Cargo` | ✅ Pass |
| `update_channel_windows_portable` *(cfg(windows))* | `C:\SonarNwork\sonar.exe` | `WindowsPortable` | ✅ Pass |
| `update_channel_unsupported_from_target_debug_or_release` | `C:\project\target\debug\sonar.exe` + `C:\project\target\release\sonar.exe` | `Unsupported` | ✅ Pass |
| `update_channel_debian` *(cfg(target_os="linux"))* | `/usr/bin/sonar` | `Debian` | ⏭️ Skip (Windows) |
| `update_channel_unsupported_linux_other` *(cfg(target_os="linux"))* | `/opt/sonar/sonar` | `Unsupported` | ⏭️ Skip (Windows) |

#### Test `confirm_update` (2 cases)

| Test | Input | Expected | Kết quả |
|---|---|---|---|
| `confirm_update_with_confirmation_returns_ok` | `confirm_update("v9.9.9", true)` | `Ok(())` | ✅ Pass |
| `confirm_update_without_confirmation_in_non_tty_returns_err` | `confirm_update("v9.9.9", false)` | `Err(...)` với message chứa "rerun with \`sonar update --yes\`" | ✅ Pass |

### 3. Kết quả test

#### `cargo test -p sonar-cli --bin sonar update::tests`

```
38 passed; 0 failed
```

#### `cargo test -p sonar-cli` (full package)

Toàn bộ pass — binary tests + integration tests.

#### `cargo test --workspace`

```
running 38 tests  -> ok. 38 passed
running 38 tests  -> ok. 38 passed
running 21 tests  -> ok. 21 passed
running 39 tests  -> ok. 39 passed
running 2 tests   -> ok. 2 passed
running 1 test    -> ok. 1 passed
running 40 tests  -> ok. 38 passed; 2 ignored
running 2 tests   -> ok. 0 passed; 2 ignored
running 22 tests  -> ok. 22 passed
(8 doc-test suites -> 0 passed each, no doc-tests exist)
```

**Tổng: 199 passed, 0 failed, 4 ignored** (≥ baseline B1: 185). Tăng 14 test (gồm các test mới + integration).

### 4. Chạy thật `sonar update`

Cả hai lệnh đều chạy vì version workspace (`0.1.3`) == version GitHub (`v0.1.3`), đảm bảo an toàn.

| Lệnh | Output | Exit code | Mutate? |
|---|---|---|---|
| `cargo run -p sonar-cli --release -- update --check` | `SonarNwork is up to date (v0.1.3).` | 0 | ❌ Không |
| `cargo run -p sonar-cli --release -- update` (không `--yes`) | `SonarNwork is up to date (v0.1.3).` | 0 | ❌ Không — không có dòng hỏi xác nhận nào |

Không có dòng "Install SonarNwork..." hoặc "Proceed with update?" nào xuất hiện. Cơ chế "không tự nâng khi chưa xác nhận" hoạt động đúng: do version bằng nhau, `run()` in "up to date" và `return Ok(())` trước khi chạm `confirm_update` hay bất kỳ channel nào.

### 5. Git status

```
M  crates/sonar-cli/src/update.rs              (modified — chỉ thêm test)
?? docs/plan/REPORT-b2-verify-self-update.md    (mới)
```

Không có file sản phẩm nào khác bị đổi.

### 6. Acceptance Criteria

| # | Tiêu chí | Kết quả |
|---|---|---|
| 1 | `curl` xác nhận `tag_name` | ✅ `v0.1.3` |
| 2 | `cargo test -p sonar-cli update::tests` exit 0 | ✅ 38 passed |
| 3 | `cargo test -p sonar-cli` exit 0 | ✅ Toàn bộ pass |
| 4 | `cargo test --workspace` exit 0, ≥ 185 test | ✅ 199 passed (≥185) |
| 5a | `sonar update --check` → "up to date", exit 0 | ✅ |
| 5b | `sonar update` (không cờ) → "up to date", exit 0, không hỏi | ✅ |
| 6 | git status chỉ có update.rs + REPORT | ✅ |

## Kết luận

✅ **B2 hoàn thành.** Tất cả acceptance criteria đạt. Cơ chế "không tự nâng khi chưa xác nhận" được test đầy đủ qua:
1. Unit test `confirm_update_without_confirmation_in_non_tty_returns_err` — khóa hành vi `Err` khi stdin không phải TTY.
2. Unit test `confirm_update_with_confirmation_returns_ok` — xác nhận `--yes` cho phép update.
3. Chạy thật `sonar update` trong điều kiện version bằng nhau — xác nhận không chạm `confirm_update` nhờ early return.
