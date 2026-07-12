# Kịch bản test người dùng — SonarNwork (bản desktop thật)

Tài liệu này để **đóng vai người dùng cuối** chạy thử app, tập trung vào các
luồng **chỉ chạy được ở bản Tauri thật** (không test được bằng browser preview):
cài đặt, Nmap, Nuclei, và mở lệnh ra terminal.

Viết cho người dùng — không cần biết code. Mỗi ca test ghi rõ: **bấm gì → mong
đợi gì → dấu hiệu SAI**. Các mục 👀 là những chỗ đã biết là dễ hiểu nhầm/dùng
sai, hãy soi kỹ.

> Chạy tài liệu này **sau khi luồng codex hiện tại dừng** (đang sửa dở nhiều file).

## Nguyên tắc an toàn (đọc trước khi test)

- **Chỉ quét mục tiêu bạn sở hữu hoặc được phép.** Dùng `127.0.0.1` (máy của
  bạn), hoặc một IP/host trong mạng LAN của bạn. **Không** quét địa chỉ công
  cộng của người khác — kể cả khi app cho phép tick "tôi được phép".
- Nmap/Nuclei là công cụ chủ động; quét bừa có thể vi phạm chính sách mạng.
- Nếu chỉ muốn thấy app chạy mà không quét gì thật: dùng target `127.0.0.1` —
  thường không có gì mở, kết quả rỗng là **bình thường**.

## Chuẩn bị & cách mở app

Cần **bản Tauri thật** (browser preview không có backend, tab Nmap/Nuclei sẽ trống).

```powershell
cd app
pnpm install            # nếu chưa cài
pnpm tauri dev          # mở app desktop ở chế độ phát triển
```

Hoặc, nếu đã có file cài đặt (xem Mục A): chạy file `.msi`/`.exe` trong
`app/src-tauri/target/release/bundle/`.

## Cách đọc mỗi ca test

- ✅ **ĐẠT nếu** — điều đúng phải xảy ra.
- ❌ **LỖI nếu** — dấu hiệu hỏng.
- 👀 **Soi kỹ** — bẫy đã biết; đây là chỗ "logic đúng nhưng dễ dùng sai".

---

## Trạng thái test hiện tại (cập nhật 2026-07-11)

Để bạn không làm lại việc đã kiểm, và biết ngay việc nào còn treo.

**✅ Đã kiểm qua CLI `sonarnwork` (chạy thật, đúng):**
- Probe thường: `info`, `entity parse`, `dns` lookup, `ping` (kể cả đích chết →
  báo lỗi đúng), `http_probe`, `tls_cert`, `fast_trace`, `reachability`.
- Verdict thất bại ở đường **structured/CLI**: **đúng** (ping đích chết ra
  exit 1, mất gói 100%, không báo "success"). → Lõi `sonar-core` của các luồng
  hằng ngày lành.

**✅ Đã kiểm qua browser preview (Vite):** bố cục, đổi ngôn ngữ/theme, chọn
workflow/probe. Đã **bắt được**: rớt dấu tiếng Việt (E6), tab scanner trống khi
không có backend, tab nav còn tiếng Anh (E8).

**🐞 Bug thật đã tái hiện (chưa sửa):**
- **E10** — `domain:port` → reachability lỗi (`example.com:443:443`).
- **E2** — Nuclei cắt scheme/path của URL (thấy trong code; xác nhận ở C2 khi có GUI).

**⏳ Chỉ bản Tauri desktop THẬT mới test được — CHƯA làm:**

Các việc dưới đây cần **backend Tauri + cửa sổ native**, không chạy được bằng CLI
hay browser preview:

| Việc | Thuộc mục | Vì sao còn chờ |
| --- | --- | --- |
| Verdict panel **live-output** báo xanh khi lệnh lỗi (E3 phần còn lại) | F2, E3 | Đường `run_probe_live` chỉ có ở GUI; CLI đã chứng minh lõi đúng |
| Nút **Install Nmap** (mở web → refresh) | B2–B3 | Cần lifecycle + mở trình duyệt từ app |
| **Tải Nuclei** (managed download) | C1 | Cần tải + ghi vào `%LOCALAPPDATA%` |
| **Mở CLI / terminal** handoff | D | Cần app spawn cửa sổ; và kiểm mở `sonar-cli` hay lệnh thô (E9) |
| **Installer** đóng gói + cài | A | Cần `tauri build` + chạy file cài |
| **Quét scanner** (Nmap/Nuclei chạy thật + Stop) | B4–B5, C2–C3 | Cần runtime + tiến trình live |

**Lý do hoãn:** bản Tauri đang bị **codex build dở** (đụng `target/`), và **cửa
sổ desktop native không lái tự động được** (Playwright chỉ lái browser). Để dành
chạy khi codex dừng — theo đúng các mục A/B/C/D bên dưới.

---

## A. Cài đặt app (Installer)

### A1. Đóng gói được file cài đặt
1. Chạy `cd app; pnpm build` rồi `pnpm tauri build`.
2. Mở thư mục `app/src-tauri/target/release/bundle/`.

- ✅ **ĐẠT nếu**: có file `.msi` (và/hoặc NSIS `.exe`) được tạo.
- ❌ **LỖI nếu**: build lỗi, hoặc không ra file cài nào.

### A2. Cài như người dùng thật
1. Chạy file `.msi`/`.exe` vừa tạo trên một máy Windows (hoặc thư mục sạch).
2. Đi hết các bước cài, mở app từ Start Menu.

- ✅ **ĐẠT nếu**: cài xong, mở được app, có icon, tên hiển thị đúng "SonarNwork".
- ❌ **LỖI nếu**: cài lỗi, mở không lên, thiếu icon/tên.
- 👀 **Soi kỹ**: Windows SmartScreen nhiều khả năng cảnh báo **"Nhà phát hành
  không xác định"** (vì app **chưa ký số**). Đây là trải nghiệm người dùng thật
  sẽ gặp — ghi lại xem có làm người dùng sợ/bỏ cuộc không. Đây là việc cần làm
  (ký số) chứ không phải lỗi code.

---

## B. Nmap — dò công cụ, cài (handoff), quét

> Nmap **không đi kèm app**. App chỉ *dò* xem máy đã cài Nmap chưa, và nếu chưa
> thì *mở trang tải về* để bạn tự cài (không tự tải).

### B1. Dò runtime khi CHƯA cài Nmap
1. Vào tab **Nmap**. Bấm **"Dò runtime"** (Detect runtime).

- ✅ **ĐẠT nếu**: app báo rõ **chưa cài / không tìm thấy**, và **không** giả vờ
  là đã có.
- ❌ **LỖI nếu**: báo "available" trong khi máy chưa hề cài Nmap.

### B2. Bấm "Cài đặt" (install handoff) — BẪY QUAN TRỌNG
1. Bấm nút **"Cài đặt"** (Install) trên tab Nmap.

- ✅ **ĐẠT nếu**: mở **trang nmap.org** trên trình duyệt để bạn tự tải bộ cài.
- 👀 **Soi kỹ (bẫy dùng-sai)**: Nút tên là "Cài đặt" nhưng **nó KHÔNG cài gì**
  — chỉ mở web. Sau khi bấm, app **vẫn báo "chưa cài"**. Người dùng rất dễ nghĩ
  "tôi bấm Cài đặt rồi mà sao chưa cài?". **Ghi lại cảm giác này.** Kỳ vọng
  đúng: sau khi cài Nmap từ web xong, phải quay lại app bấm **"Dò runtime"** thì
  mới nhận. Nếu nhãn/nội dung nút không nói rõ điều đó → tính là **lỗi trải
  nghiệm** cần sửa (đổi chữ nút, hoặc thêm hướng dẫn 2 bước).

### B3. Dò lại sau khi đã cài Nmap thật
1. Cài Nmap từ nmap.org (chọn cả bản kèm PATH). Quay lại app, bấm **"Dò runtime"**.

- ✅ **ĐẠT nếu**: app hiện **đường dẫn + phiên bản** Nmap, trạng thái "available".
- ❌ **LỖI nếu**: đã cài mà vẫn không dò ra (kiểm tra Nmap có trong PATH chưa).

### B4. Quét cổng loopback (an toàn)
1. Ô target: nhập `127.0.0.1`.
2. Tick **"Tôi sở hữu hoặc được phép quét mục tiêu này"**.
3. Bấm **"Xem lệnh"** (Preview) → xem lệnh sẽ chạy.
4. Bấm **"Chạy trong app"** (Run in app) → xem output cuộn ra.

- ✅ **ĐẠT nếu**: lệnh preview có dạng `nmap -sT ... --top-ports 100 ... 127.0.0.1`;
  chạy xong hiện tóm tắt (số cổng mở, hosts up, exit code).
- ❌ **LỖI nếu**: chưa tick scope mà vẫn bấm Chạy được; hoặc target trống/rỗng
  mà nút vẫn bật.
- 👀 **Soi kỹ (bẫy tick phản xạ)**: checkbox scope **là cửa duy nhất** — không có
  kiểm tra allowlist phía sau. Thử tick rồi nhập một IP **không phải của bạn**
  (đừng bấm Chạy) và tự hỏi: app có làm gì để ngăn bạn quét nhầm không? Nếu chỉ
  dựa vào bạn tick cho đúng → ghi nhận là **rủi ro dùng-sai**.

### B5. Dừng giữa chừng (Stop)
1. Chạy Nmap, trong lúc đang chạy bấm **"Dừng"** (Stop).

- ✅ **ĐẠT nếu**: tiến trình dừng, **phần output đã nhận vẫn giữ nguyên** (không mất).
- ❌ **LỖI nếu**: bấm Dừng mà không dừng, hoặc mất sạch output đã có.

---

## C. Nuclei — cài managed (tải về), quét, cập nhật

> Nuclei là loại **app tự quản** (tải về `%LOCALAPPDATA%\SonarNwork\tools`),
> chỉ cài khi bạn bấm rõ ràng, không bao giờ tự cài lúc mở app.

### C1. Cài Nuclei (managed download) — CHÚ Ý THỜI GIAN
1. Vào tab **Nuclei**. Bấm **"Cài đặt"** (Install).

- ✅ **ĐẠT nếu**: app tự tải bản Windows chính thức từ ProjectDiscovery, kiểm tra
  rồi báo cài xong, hiện phiên bản.
- ❌ **LỖI nếu**: báo cài xong nhưng dò lại không thấy; hoặc tải từ nguồn lạ
  (không phải `github.com/projectdiscovery/nuclei/releases/download/...`).
- 👀 **Soi kỹ (bẫy "tưởng treo")**: file Nuclei khá lớn (hàng chục–trăm MB). Nút
  chỉ hiện **"Working..."** không có thanh tiến độ. Bấm xong **hãy đợi**, đừng
  bấm lại nhiều lần. Ghi lại: bạn có tưởng app treo không? Nếu có → cần **hiển
  thị tiến độ tải** (việc nên làm).

### C2. Quét một URL bạn sở hữu — BẪY LOGIC ĐÃ BIẾT
1. Ô target đang mặc định `https://127.0.0.1`. **Đổi thành** một URL có đường dẫn,
   ví dụ `https://127.0.0.1/abc` (hoặc một URL nội bộ bạn sở hữu, có path).
2. Tick scope. Bấm **"Xem lệnh"** (Preview).
3. **Đọc kỹ lệnh preview**, chú ý phần sau `-u`.

- ✅ **ĐẠT nếu**: lệnh giữ **nguyên URL bạn nhập**, ví dụ `nuclei -u https://127.0.0.1/abc ...`.
- ❌ **LỖI nếu (bug đã phát hiện)**: lệnh bị **cắt còn `-u 127.0.0.1`** — mất
  `https://` và mất `/abc`. Nghĩa là app quét **không đúng URL bạn đã xác nhận
  scope**. Đây là **lỗi thật cần sửa**; nếu thấy đúng như vậy, đánh dấu FAIL.

### C3. Chạy Nuclei và xem kết quả
1. Với target `https://127.0.0.1` (loopback), bấm **"Chạy trong app"**.

- ✅ **ĐẠT nếu**: chạy xong hiện tóm tắt (số finding, số high/critical, exit code);
  loopback thường **0 finding** — đó là bình thường.
- ❌ **LỖI nếu**: lỗi mà app báo thành công (xem C-bẫy bên dưới).

### C4. Cập nhật Nuclei
1. Sau khi đã cài, nút chuyển thành **"Cập nhật"** (Update). Bấm thử.

- ✅ **ĐẠT nếu**: tải bản mới, thay thế an toàn, báo phiên bản mới (hoặc "đã mới nhất").
- ❌ **LỖI nếu**: hỏng bản đang có khi cập nhật lỗi (phải giữ bản cũ nếu tải lỗi).

---

## D. "Mở CLI" — chạy tiếp bằng CLI của SonarNwork

> **Quyết định (2026-07-11):** **bỏ lựa chọn PowerShell/CMD**, tập trung vào
> **CLI của SonarNwork**. Nút "Mở CLI" giờ chạy `sonarnwork ...` (không còn dán
> lệnh thô, không còn toggle shell).

### D1. Đã triển khai — mở đúng CLI của sản phẩm
1. Ở một probe/tool đã có preview, bấm **Mở CLI**.

- ✅ **ĐẠT nếu**: cửa sổ chạy **`sonarnwork ...`** — vd
  `sonarnwork scanner run nmap 127.0.0.1 --yes` (scanner) hoặc `sonarnwork myip`
  (probe). Code: `scanner_cli_invocation` / `probe_cli_invocation`, program = `sonarnwork`.
- ❌ **LỖI nếu**: vẫn dán lệnh thô hệ điều hành (`ping`/`nmap` trần).

### D2. E9 — ĐÃ SỬA (re-baseline)
E9 cũ = "Mở CLI mở lệnh thô, không phải sonar-cli". Nay build `sonarnwork` CLI →
**PASS (đã sửa)**. (Cửa sổ host vẫn là PowerShell, nhưng lệnh bên trong là CLI
sản phẩm — đúng ý.)

### ~~D3. Chọn PS/CMD~~ — ĐÃ BỎ (retired)
Tính năng chọn PowerShell/CMD đã bỏ khỏi UI (không còn `terminalShell`, nút không
truyền `shell`). Ca test này **retire**, không chạy nữa. Backend còn nhánh `cmd`
nhưng UI không gọi tới → có thể là **dead code cần dọn** (ghi nhận, không test).

### D4. Trạng thái lỗi & biên — BẮT BUỘC thử (đây là chỗ hay hỏng)

Áp theo [Mẫu test handoff/launch](test/WORKFLOW.md#mẫu-test-cho-tính-năng-handofflaunch).

| # | Thử | ✅ ĐẠT | ❌ / 👀 |
| --- | --- | --- | --- |
| D4a | **Tự chạy hay dán-chờ?** Bấm mở, nhìn cửa sổ | đúng theo yêu cầu sản phẩm | 👀 hiện tại `-NoExit -Command`/`/K` = **tự chạy ngay**. Nếu yêu cầu là "dán để người dùng xem/sửa rồi mới chạy" → **LỖI** |
| D4b | **Không mở được / mở lỗi** (vd cmd/start fail) | app **báo lỗi rõ** trên UI | ❌ im lặng, hoặc UI treo như đã mở mà thực ra không |
| D4c | **Target ký tự lạ** (`a b`, `a;b`, `a&b`, `a"b`) | lệnh escape đúng, không chạy nhầm/không tách lệnh | ❌ lệnh hỏng, thừa/thiếu tham số, hoặc **injection** (chạy phần sau `;`/`&`) |
| D4d | **Nền không phải Windows** | báo "chỉ hỗ trợ Windows" rõ ràng | ❌ im lặng / crash |
| D4e | **Command override bị scope từ chối** | báo lỗi, **không mở** | ❌ vẫn mở lệnh chưa được phép |
| D4f | **Bấm liên tục nhiều lần** | hành vi đoán trước được | 👀 đẻ ra một đống cửa sổ rác? |

Ghi rõ: **D4a là câu hỏi spec** — "Mở CLI" nên *tự chạy* hay *dán-chờ*? Ca test
đối chiếu với ý định sản phẩm; hiện trạng là **tự chạy**.

---

## F. Probe thường — luồng dùng hằng ngày (ping/traceroute/DNS/HTTP/TLS)

Nhóm dùng nhiều nhất: chạy thẳng từ máy bạn, **không cần cài gì thêm**, an toàn.
Làm trong app (tab **"Local → Internet / target"**), hoặc kiểm song song bằng
`sonar-cli` (xem cuối mục).

### F1. Public IP + DNS whoami
1. Chọn thẻ **"Public IP + DNS whoami"** → bấm **"Chạy"**.
- ✅ **ĐẠT nếu**: hiện IP công khai + DNS đang dùng; verdict rõ.
- ❌ **LỖI nếu**: trống/lỗi trong khi máy đang có mạng.

### F2. Ping
1. Target `1.1.1.1` → chọn **Ping** → **Chạy**.
- ✅ **ĐẠT nếu**: verdict + các dòng latency / tỉ lệ mất gói.
- 👀 **Soi kỹ (bẫy E3)**: thử target chắc chắn không tới (vd một IP nội bộ chết
  như `192.0.2.1`) — verdict phải là **cảnh báo/lỗi**, **không** xanh "hoàn tất".

### F3. Traceroute / MTR / Fast trace / Path MTU
1. Target `1.1.1.1` → lần lượt chọn **Traceroute**, **MTR / pathping**,
   **Fast trace**, **Path MTU** → **Chạy**.
- ✅ **ĐẠT nếu**: hiện đường đi theo hop / mẫu latency / ước lượng MTU; mỗi loại
  cho kết quả **khác nhau** đúng bản chất của nó.
- ❌ **LỖI nếu**: các loại cho ra kết quả giống hệt nhau, hoặc treo không phản hồi.

### F4. DNS lookup + DNS leak check
1. Target `example.com` → **DNS lookup** (chọn record A) → **Chạy**.
2. Chọn **DNS leak check** → **Chạy**.
- ✅ **ĐẠT nếu**: lookup trả bản ghi A; leak check hiện DNS **cấu hình** vs DNS
  **quan sát được** và chỉ ra có lệch không.
- ❌ **LỖI nếu**: không phân giải được domain phổ biến; hoặc leak check không nêu
  được resolver nào.

### F5. HTTP probe
1. Target `example.com` (hoặc `https://example.com`) → **HTTP probe** → **Chạy**.
- ✅ **ĐẠT nếu**: hiện HTTP status + tóm tắt header; verdict hợp lý (2xx/3xx = ổn).
- 👀 **Soi kỹ**: thử một host không có web (vd `1.1.1.1:81`) — lỗi kết nối phải
  hiện **cảnh báo**, không báo thành công.

### F6. TLS certificate
1. Target `example.com` → **TLS certificate** → **Chạy**.
- ✅ **ĐẠT nếu**: hiện thông tin handshake + chứng chỉ (CN, hạn dùng...).
- ❌ **LỖI nếu**: chứng chỉ hợp lệ mà báo lỗi, hoặc ngược lại.

### Kiểm song song bằng `sonar-cli` (tuỳ chọn)
Nếu muốn đối chiếu bằng dòng lệnh của chính sản phẩm:
```powershell
sonar-cli myip
sonar-cli ping 1.1.1.1 --count 4 --timeout 1000
sonar-cli trace 1.1.1.1
sonar-cli dns example.com --record A
sonar-cli check example.com
sonar-cli probe run web.http_probe example.com
sonar-cli probe run web.tls_cert example.com
```
- ✅ **ĐẠT nếu**: kết quả CLI **khớp** với kết quả trong app (cùng `sonar-core`).
- ❌ **LỖI nếu**: app và CLI cho verdict khác nhau cho cùng target — nghĩa là có
  chỗ shell tự diễn giải khác core.

---

## G. Hướng / nguồn đo (màu) — phân biệt "mạng của bạn" vs remote vantage vs lookup

App tô màu mỗi kiểm tra theo **nguồn phát của phép đo**. Mục tiêu test: mỗi probe
phải **màu + nhãn khớp đúng nguồn**, vì app hay lẫn (dùng 2 mapping song song
`directionClass` (màu) và `directionLabel` (chữ), lại có catch-all "outbound").

**Ba nhóm nguồn người dùng cần phân biệt được ngay bằng mắt:**

| Nhóm | Nghĩa | Gồm probe | Màu mong đợi |
| --- | --- | --- | --- |
| **Mạng của bạn** | đo phát ra **từ máy/LAN/IP-WAN của bạn** đi ra | local.\*, connectivity.\* (ping, traceroute, mtr, path_mtu, fast_trace, reachability, route_check), dns.lookup, dns.leak_check, web.http_probe, web.tls_cert, public.egress_check | **cam** (app chia nội bộ `local` + `outbound` — cả hai đều là "mạng của bạn") |
| **Remote vantage** | đo **từ điểm bên ngoài** vào bạn (không phải mạng bạn) | public.port_check, remote-scan, globalping | khác cam (vd xanh) |
| **Tra cứu** | **không đụng mạng bạn** — chỉ tra sổ đăng ký | recon.whois_rdap (WHOIS/RDAP) | khác cam (vd xám) |

- **G1 — màu khớp nguồn**: mở app, chọn lần lượt từng probe, nhìn **màu card +
  panel + nhãn hướng**.
  - ✅ **ĐẠT nếu**: màu + nhãn đúng nhóm ở bảng trên (whois = tra cứu, ping = mạng
    của bạn, public port check = remote vantage).
  - ❌ **LỖI nếu**: whois/RDAP tô như "outbound/mạng của bạn"; hoặc public port
    check tô như "mạng của bạn"; hoặc ping/http tô như remote.
- **G2 — nhãn và màu không mâu thuẫn**: `directionLabel` (chữ) và `directionClass`
  (màu) phải kể **cùng một nguồn**.
  - 👀 **Soi kỹ**: `recon.*` hiện nhãn "public records" nhưng class "lookup" —
    người đọc dễ tưởng "public = remote vantage". Ghi lại nếu chữ và màu đá nhau.
- **G3 — probe mới không rơi nhầm catch-all**: `directionClass` trả "outbound"
  (cam) cho **mọi thứ không khớp luật**. Nên probe mới lạ sẽ **mặc định thành cam**
  dù thực chất là remote/lookup.
  - 👀 Mỗi lần thêm probe: kiểm màu của nó trước khi coi là xong.

## H. Scope & mục tiêu thật — test bằng domain phổ biến, và bắt E13

Test bằng **domain thật**, nhưng **phân theo mức rủi ro của probe**:

- **Safe-active** (ping, traceroute, mtr, http, tls, dns, reachability, egress):
  dùng **domain thật phổ biến** — `youtube.com`, `facebook.com`, `example.com`,
  `cloudflare.com`. Đây là **đo hợp lệ**, không phải tấn công.
- **Scanner** (nmap, nuclei): **CHỈ** `127.0.0.1` / IP-LAN **của bạn**. **KHÔNG bao
  giờ** quét youtube/facebook — quét cổng/lỗ hổng hạ tầng người khác là **phi pháp**.

- **H1 — CLI với domain thật**: `sonarnwork ping youtube.com`,
  `sonarnwork probe run web.http_probe facebook.com`.
  - ✅ **ĐẠT nếu**: chạy được (CLI dùng `for_explicit_target` → tự cho phép target
    bạn gõ).
- **H2 — GUI cùng domain (bắt E12)**: nhập `youtube.com` vào app, chạy ping/HTTP.
  - ❌ **LỖI (hiện trạng)**: app báo **`scope denied: active probe requires an
    explicitly allowed target`** — vì GUI dùng `AppCore::default()` (chặn), khác
    CLI. **Không có nút cấp phép** → workflow "Local → Internet" kẹt.
  - ✅ **ĐẠT khi**: app cho chạy target bạn tự gõ (như CLI), hoặc có nút "cho phép
    mục tiêu này". Đây là ca test **chốt E13** — chạy để biết đã sửa chưa.
- **H3 — scanner chỉ loopback**: nmap/nuclei phải bắt tick "tôi được phép" và chỉ
  nên nhắm `127.0.0.1`.
  - 👀 **Soi kỹ**: đừng bao giờ điền domain người khác vào Nmap/Nuclei khi test.

## E. Bảng kiểm nhanh các bẫy "logic đúng nhưng dùng sai cách"

Đây là các điểm đã biết trước; test xong tick từng cái:

| # | Bẫy | Cách kiểm nhanh | Kết luận mong đợi |
| --- | --- | --- | --- |
| E1 | Nút "Cài đặt" Nmap **không cài**, chỉ mở web | B2 | Cần đổi chữ/nói rõ 2 bước |
| E2 | **Nuclei cắt mất scheme/path** của URL | C2 | **Bug — phải sửa** |
| E3 | Lệnh live **thất bại vẫn hiện xanh "hoàn tất"** (chỉ ở **live GUI**) | Chạy một lệnh chắc chắn lỗi, xem verdict | Exit ≠ 0 phải hiện cảnh báo, không xanh. **Đã kiểm CLI/structured: ĐÚNG** (ping đích chết → báo lỗi exit 1). Chỉ còn nghi ở panel live desktop. |
| E4 | Checkbox scope **tick phản xạ**, không có allowlist | B4 | Cân nhắc thêm ma sát/xác nhận |
| E5 | Tải Nuclei **không có tiến độ** → tưởng treo | C1 | Cần thanh tiến độ |
| E6 | **Rớt dấu tiếng Việt** ở panel Public ingress, subtitle Nmap/Nuclei | Mở các tab đó, đọc chữ | Sửa chữ + gom về i18n |
| E7 | Installer **chưa ký số** → SmartScreen dọa | A2 | Cần ký số trước khi phát hành |
| E8 | Tab điều hướng **vẫn tiếng Anh** khi đang ở chế độ VI | Bật VI, nhìn các tab trên cùng | Dịch nhãn tab |
| E9 | Nút "Mở CLI" **mở terminal máy chạy lệnh thô**, không mở `sonar-cli` | D1–D2 | Sửa hành vi gọi `sonar-cli`, hoặc đổi nhãn nút |
| E10 | **`domain:port` bị hiểu nhầm thành URL** → reachability lỗi `host:port:port` | F, hoặc CLI `reachability example.com:443` | **Bug thật — đã tái hiện.** `example.com:443` parse ra `url:` thay vì `port:`; cần sửa entity parser |

### Về E3 (cách tạo một lần chạy chắc chắn lỗi)
Dễ nhất: ở probe thường, mở terminal-edit và sửa lệnh thành một lệnh sai (ví dụ
đổi tên chương trình thành thứ không tồn tại) rồi chạy live; hoặc ping tới một
địa chỉ chắc chắn không tới. Xem **ô verdict** (pill trạng thái):
- ✅ đúng: hiện **cảnh báo/không-ổn**, không phải xanh "hoàn tất".
- ❌ sai: vẫn xanh "Live command completed" dù exit code khác 0.

---

## Ghi kết quả

Với mỗi ca (A1…D2, E1…E8), ghi: **ĐẠT / LỖI / Ghi chú**. Với mục LỖI, chụp màn
hình và mô tả "bạn mong đợi gì, thực tế thấy gì". Ưu tiên báo các LỖI thuộc nhóm
**E2, E3** (lỗi thật) và **E6** (mất dấu — người dùng thấy ngay).

## Ghi chú cho lập trình viên (không cần cho người test)

Vị trí liên quan khi sửa: bug Nuclei-URL ở `command_target`/`scanner_invocation`
(`crates/sonar-core/src/probe.rs`, `app/src-tauri/src/lib.rs`); verdict live ở
`resultVerdict` (`app/src/App.tsx`); rớt dấu ở các hàm readiness/subtitle trong
`App.tsx` + `i18n/copy.ts`; tab scanner trống khi không có backend do
`fallbackManagedTools()` trả rỗng.
