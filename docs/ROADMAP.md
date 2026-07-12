# Lộ trình phát triển SonarNwork

Đây là **bản đồ tính năng** của SonarNwork, viết cho người dùng/chủ sản phẩm —
không cần biết code. Nhìn vào là biết: app đang có gì, cái gì **dùng được**,
cái gì **hiện ra nhưng chưa chạy**, và **làm gì tiếp theo, theo thứ tự nào**.

Mọi việc phát triển đi qua pipeline `/spec → /plan → /build → /test → /review →
/ship` (plugin `delivery-pipeline`). Chi tiết kỹ thuật của từng tính năng khi
làm sẽ nằm ở `.delivery/<tên-tính-năng>/`, còn file này chỉ giữ bức tranh lớn.

## Cách đọc ký hiệu

| Ký hiệu | Nghĩa |
| --- | --- |
| ✅ | **Dùng được** — bấm là chạy, có kết quả thật |
| 🟡 | **Có trong app nhưng chưa chạy được** — mới là mô tả/khung, bấm chưa ra việc |
| 📋 | **Đã lên kế hoạch** — chưa bắt đầu code |
| 🔴 | **Chưa có** — cần thêm mới |

## Tính năng hiện tại (chụp từ code, 2026-07-10)

### ✅ Dùng được ngay

| Tính năng | Người dùng làm được gì |
| --- | --- |
| **Kiểm tra máy/LAN nội bộ** | Xem card mạng, IP nội bộ, gateway, DNS resolver, cổng đang lắng nghe, bảng route |
| **Kiểm tra từ máy ra Internet/mục tiêu** | Public IP, tra DNS, ping, traceroute, HTTP, TLS — chạy từ máy của bạn |
| **Tra cứu WHOIS / RDAP** | Tra thông tin đăng ký công khai của domain, IP, URL, host:port |
| **Chẩn đoán đường đi nâng cao** | fast-trace, MTR, path-MTU, kiểm tra route, DNS leak check |
| **Giải thích kết quả cho người mới** | Mỗi kết quả có tóm tắt, kết luận (tốt/cảnh báo/lỗi), và gợi ý bước tiếp theo |
| **Xem trước & mở lệnh ra terminal** | Xem lệnh sẽ chạy, hoặc mở ra terminal hệ thống để tự chạy |

Tổng ~13 loại kiểm tra (probe) đã chạy thật và có test bảo vệ.

### 🟡 Có trong app nhưng CHƯA chạy được

| Tính năng | Hiện trạng thật | Vì sao chưa chạy |
| --- | --- | --- |
| **Nmap** (quét cổng/dịch vụ) | Plugin tùy chọn: dò runtime, mở trang cài chính thức, preview, chạy trong app hoặc CLI | Không bundle; người dùng hoàn tất system installer rồi bấm dò lại |
| **Nuclei** (quét lỗ hổng theo template) | Plugin tùy chọn app-managed: cài/update thủ công, preview, chạy trong app hoặc CLI | Chỉ hỗ trợ managed installer Windows ở lát cắt đầu; luôn cần xác nhận phạm vi |
| **Các công cụ ngoài khác** (httpx, naabu, subfinder, dnsx, trippy, nexttrace) | Nằm trong danh mục công cụ | Chỉ là danh mục + link cập nhật; chưa có phần thực thi |
| **Kiểm tra cổng công khai** (public port check) | Hiện trong tab "Public ingress" | Đánh dấu *đã lên kế hoạch*; cần điểm quét từ xa có phạm vi rõ |
| **Đo từ xa** (Globalping / remote scan) | App tạo được "kế hoạch đo" | Mới dừng ở kế hoạch, chưa thực thi đo thật; cần token + vị trí + phạm vi |

Đây chính là khoảng trống bạn đã nhận ra: **các công cụ mạnh (nmap, nuclei…)
xuất hiện trên giao diện nhưng chưa quét được** vì chưa có "bộ chạy công cụ
ngoài" phía sau.

### 🔴 Chưa có

| Tính năng | Ghi chú |
| --- | --- |
| **Bản cài đặt (installer)** | Chưa đóng gói được file cài đặt Windows để phát hành cho người dùng |
| **Bộ chạy công cụ ngoài** | Chưa có phần dò công cụ đã cài, tự tải/cài, và chạy rồi đọc kết quả |
| **Đo từ xa thật** | Chưa gọi được dịch vụ đo từ xa và nhận kết quả về |

## Việc cần làm tiếp — theo thứ tự

Nguyên tắc: **rủi ro tăng dần**. Làm cái nhỏ/an toàn trước để chạy thử quy
trình, việc nặng về bảo mật để sau khi pipeline đã đáng tin.

### Phase 0 — Nền tảng xanh — ✅ XONG (2026-07-10)

Đã chạy và tất cả đạt:

- `cargo test --workspace` — **31 test qua**, 0 lỗi.
- `pnpm test` (app) — **8 test qua**.
- `pnpm build` (app) — build bản production thành công.

Nghĩa là bộ kiểm thử mà mọi bước sau dựa vào đang sạch.

### Phase 1 — Đóng gói bản cài đặt 📋

**Mục tiêu:** tạo được file cài đặt Windows (NSIS/MSI) chạy được, và chạy thử
đúng file đó. Chọn làm trước vì nhỏ, ít rủi ro, và **mọi tính năng sau đều cần
nó khi phát hành**.

### Phase 2 — Bộ chạy công cụ ngoài (để Nmap/Nuclei thật sự dùng được) 🚧

**Mục tiêu:** biến các thẻ 🟡 thành ✅. Xây phần phía sau để app có thể **dò
công cụ đã cài → (tùy chọn) tải/cài → chạy → đọc kết quả**.

Thứ tự đề xuất trong phase này (mỗi công cụ là một vòng pipeline nhỏ):

1. ✅ Contract plugin, lifecycle, scope và interaction dùng chung.
2. ✅ **Nmap** — system installer handoff, dò runtime, preview/run/CLI có phạm vi.
3. ✅ **Nuclei** — managed install/update thủ công trên Windows, preview/run/CLI,
   bắt buộc khai báo phạm vi và không bao giờ bật mặc định.
4. 📋 Mở rộng cùng contract sang httpx, dnsx, subfinder, naabu, Trippy/NextTrace.

### Phase 3 — Đo từ xa & kiểm tra cổng công khai 📋

**Mục tiêu:** các tính năng giá trị cao nhưng nặng về bảo mật, làm sau cùng.

- **Đo từ xa thật** (Globalping / remote scan): token, vị trí, phạm vi rõ ràng.
- **Kiểm tra cổng công khai**: chuyển từ *đã lên kế hoạch* sang *dùng được* qua
  điểm quét từ xa có phạm vi.

## Bạn muốn thêm/sửa một tính năng thì làm thế nào

Bạn **không cần mô tả kỹ thuật**. Chỉ cần nói ngắn gọn, ví dụ:
*"Cho tôi quét cổng bằng Nmap ngay trong app"* hoặc *"Thêm kiểm tra chuỗi
chuyển hướng HTTP"*. Sau đó:

1. Tôi hỏi lại 1–3 câu nếu có chỗ mơ hồ làm đổi phạm vi (ví dụ: quét bao nhiêu
   cổng, có cần quyền không).
2. `/spec` biến câu của bạn thành yêu cầu có tiêu chí rõ ràng → bạn duyệt.
3. `/plan → /build → /test → /review → /ship` lo phần còn lại.
4. Mỗi bước để lại một file trong `.delivery/<tên-tính-năng>/`; tôi chỉ dừng
   hỏi bạn ở chỗ cần quyết định.

Nếu kết quả chưa đúng ý: ta không làm lại từ đầu — chỉ chỉ ra chỗ lệch trên bản
yêu cầu (`spec.md`), sửa chỗ đó rồi chạy lại phần chênh.

## Luật cố định

- Mỗi lúc chỉ có **một tính năng là nguồn sự thật**; mỗi bước đọc file của bước
  trước trong `.delivery/<tên-tính-năng>/`.
- **Phạm vi bảo mật của công cụ quét là cửa bắt buộc**, không bỏ qua.
- **Không tự ý commit, gắn tag hay phát hành** nếu bạn chưa cho phép rõ ràng.
- `/test` phát hiện lỗi thiết kế thì quay về `/plan`, không vá tạm.

## Chọn mức pipeline để không phí token

Pipeline là công cụ kiểm soát rủi ro, không phải thủ tục bắt buộc cho mọi thay
đổi. Luôn chọn mức nhỏ nhất vẫn đủ an toàn:

| Mức | Dùng khi | Flow | Artifact |
| --- | --- | --- | --- |
| **Direct** | Sửa chữ, CSS nhỏ, lỗi hiển thị rõ nguyên nhân | làm ngay → kiểm tra tập trung | Không tạo |
| **Compact** | Một probe hoặc tính năng vừa, phạm vi rõ | spec gọn → build → test; gộp review khi phù hợp | Một file `.delivery/<feature>/work.md` |
| **Full** | Nmap/Nuclei runner, remote scan, auth/scope, migration, thao tác phá huỷ hoặc phát hành | spec → plan → build → test → review → ship | Đủ artifact theo từng gate |

Quy tắc chọn:

- Người dùng có thể yêu cầu rõ mức muốn dùng; lựa chọn đó được ưu tiên.
- Nếu đang ở Direct/Compact nhưng phát hiện rủi ro lớn hơn, nâng mức trước khi
  tiếp tục.
- Không tự hạ Nmap, Nuclei, quét mạng từ xa, quyền truy cập, secret, migration,
  thao tác phá huỷ hoặc publish xuống dưới Full.
- Không đọc lại hoặc sinh tài liệu không cần cho mức đã chọn.
- Chi phí pipeline phải tỷ lệ với rủi ro và độ mơ hồ, không tỷ lệ với số dòng code.
