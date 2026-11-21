# Các lỗi đã sửa

## server.js
1. **Body quá lớn bị cắt im lặng** (`readRawBody`): trước đây vượt 10 MB thì dữ liệu bị cắt và request vẫn chạy tiếp với body hỏng. Giờ trả `413`.
2. **Body quá lớn trên API trả 500**: error handler toàn cục không đọc mã lỗi của `express.json`. Giờ trả `413` (quá lớn) hoặc `400` (JSON sai).
3. **So sánh mật khẩu không an toàn về thời gian**: đổi sang `crypto.timingSafeEqual`.
4. **Không có giới hạn đăng nhập sai**: thêm giới hạn 10 lần sai / 15 phút theo IP, trả `429` khi vượt.
5. **Session hết hạn không bao giờ bị xóa** (rò rỉ bộ nhớ): thêm bộ dọn định kỳ mỗi 10 phút.
6. **WebSocket `/proxy-ws` bỏ qua kiểm tra Host** mà `/ws` có: nay áp dụng cùng kiểm tra.
7. **Cảnh báo mật khẩu mặc định**: khi `DEMO_PASSWORD` là `admin123`, server in cảnh báo lúc khởi động.

## proxyEngine.js
8. **Thông báo lỗi sai giới hạn**: báo "20 MB" trong khi hằng số thực tế là 50 MB. Nay thông báo lấy từ hằng số.
9. **Nhánh fallback không kiểm tra kích thước** (minimal fetch, HTTP/2): nay trả 413 khi vượt giới hạn, thay vì cắt im lặng (HTTP/2) hoặc không kiểm tra (minimal fetch).
10. **Fallback curl không giải nén gzip/br**: thiếu `--compressed`, nên trình duyệt nhận byte nén mà không có header `Content-Encoding` (đã bị strip). Đã thêm `--compressed`.
11. **Session proxy không bao giờ hết hạn** (rò rỉ bộ nhớ): thêm bộ dọn sau 24 giờ.

## Còn lại (chưa sửa, cần quyết định thiết kế)
- SSRF qua DNS rebinding: hệ thống resolve DNS để kiểm tra, nhưng `fetch` resolve lại lần nữa khi gửi request.
- `trust proxy = true` cho phép client giả `X-Forwarded-For`; `clientIp` lấy từ `cf-connecting-ip` cũng có thể giả. Chỉ ảnh hưởng hiển thị và giới hạn đăng nhập.
- Các API proxy (`/api/proxy/*`) không yêu cầu đăng nhập.
- File `.env` đang chứa mật khẩu mặc định `admin123`; nên đổi trước khi mở ra mạng.

## Đợt 2

### public/app.js
12. **Trang trong proxy điều khiển được shell trình duyệt** (lỗ hổng bảo mật): listener `message` nhận mọi message mà không kiểm tra nguồn. Trang web bên thứ ba đang mở trong proxy có thể gửi `proxy:open-tab` để mở URL tùy ý, hoặc `proxy:virtual-fullscreen` để đổi tab đang hiển thị. Nay chỉ xử lý message từ iframe proxy của chính shell (`event.source`), và `proxy:open-tab` chỉ chấp nhận `http:`/`https:`.

### public/console.js
13. **XSS qua thông báo lỗi**: `err.message` được chèn vào `innerHTML`. Nay được escape.
14. **Lỗi bị nuốt im lặng**: thêm/sửa/xóa item và đăng xuất không có `catch`, gây unhandled rejection và không báo gì cho người dùng. Nay lỗi được ghi vào log WebSocket.
15. **WebSocket chết vĩnh viễn sau khi đứt**: thêm tự kết nối lại với backoff (1s → 30s).
16. **`apiFetch` ghi đè header**: `...options` đứng sau `headers` nên truyền `headers` sẽ làm mất `Content-Type`. Đã sửa thứ tự.

## Đợt 3

### proxyEngine.js
17. **DNS rebinding**: `validateTargetUrl()` chỉ kiểm tra DNS một lần, còn `fetch` resolve lại khi kết nối. Kẻ tấn công có thể đưa DNS trả về IP công khai lúc kiểm tra và IP nội bộ lúc kết nối. Nay mọi kết nối HTTP/HTTPS đi qua undici `Agent` với `checkedLookup`, kiểm tra từng IP thật đang được dùng. Lỗi chặn trả 403 với lý do rõ ràng.
18. **XSS trong reader mode**: `buildReaderHtml` chỉ xóa `<script>`, còn giữ `onerror`, `onclick`, `href="javascript:..."`, `<form>`, `<base>`. Nội dung này được render trên cùng origin với app, nên có thể gọi `/api/items` bằng cookie đăng nhập. Nay làm sạch toàn bộ các thuộc tính và thẻ nguy hiểm. Đã kiểm tra bằng payload thật.

### package.json
- Thêm dependency `undici@6` (dùng cho `Agent` có lookup kiểm tra IP).

## Còn lại (cần quyết định thiết kế)
- **Trang proxy chạy cùng origin với app**: JavaScript của trang bên thứ ba (qua `/b/...`) có cùng origin với `localhost:11643`, nên có thể gọi `/api/items` bằng cookie phiên. Đây là rủi ro lớn nhất còn lại. Cách sửa đúng là phục vụ proxy trên origin/subdomain riêng, hoặc dùng CSP sandbox. Cả hai đều thay đổi cách hoạt động của proxy nên cần bạn quyết định.
- **Luồng HTTP/2 và curl fallback** vẫn resolve DNS riêng, không đi qua `checkedLookup`. Rủi ro rebinding còn lại chỉ ở nhánh fallback.
- `/api/proxy/*` không yêu cầu đăng nhập; `ALLOWED_HOSTS` để trống; `.env` còn mật khẩu mặc định.

## Đợt 4

### proxyEngine.js
19. **HTTP/2 và curl fallback bỏ qua kiểm tra IP** (phần còn lại của DNS rebinding): nhánh HTTP/2 nay dùng `tls.connect` với `lookup: checkedLookup`. Nhánh curl resolve và kiểm tra IP một lần, rồi ghim vào IP đó bằng `--resolve`, nên curl không thể resolve lại sang IP khác.

Đã kiểm tra: lint sạch, test suite pass, và `10.0.0.1` vẫn bị chặn 403.

## Đợt 5: tách origin proxy (cách làm tốt nhất)

Vấn đề gốc: trang bên thứ ba trong proxy chạy cùng origin với app, nên JS của chúng gọi được `/api/items` bằng cookie đăng nhập.

### server.js
20. **Proxy có origin riêng**: `PROXY_PORT` (mặc định 11644) là listener riêng, chỉ phục vụ `/b/`, `/p/`, `/proxy`, `/proxy-ws`, `/api/proxy/*`. Origin app (11643) không còn phục vụ proxy (trả 404 kèm hướng dẫn), và origin proxy không phục vụ API app.
21. **CORS phản chiếu mọi origin đã bị gỡ**: trước đây `cors({credentials:true})` phản chiếu mọi origin, cho phép trang lạ đọc response có cookie. Nay không còn CORS trên origin app. Trên origin proxy, chỉ `/api/proxy/*` có CORS và chỉ cho origin app đáng tin (`isTrustedAppOrigin`).
22. **WebSocket kiểm tra Origin**: `/ws` và `/proxy-ws` từ chối (403) origin lạ, chống cross-site WebSocket hijacking và việc dùng server làm relay.
23. **SSRF tới cả hai cổng**: `validateTargetUrl` chặn loopback tới cả `PORT` lẫn `PROXY_PORT`.
24. **`/app-config.js`**: cung cấp cho shell cấu hình origin proxy (không cần biết trước).

### public/app.js
25. Shell tạo iframe, gọi `/api/proxy/*` và mở tab tới origin proxy (`getProxyOrigin()`). Gọi `/api/proxy/*` dùng `credentials: 'include'`.
26. **In trang**: `contentWindow.print()` không dùng được với iframe khác origin (và lỗi bị nuốt). Nay shell gửi `proxy:print` qua postMessage, shim trong trang proxy tự in.

### scripts/test-connectivity.js
- Các test proxy chuyển sang `PROXY_PORT`. Thêm test cô lập origin, CORS, và WebSocket Origin. Kết quả: 19/19 pass.

### Cấu hình
- `.env`, `.env.example`: thêm `PROXY_PORT`, `PROXY_ORIGIN`, `APP_ORIGINS`.
- `scripts/windows-firewall.ps1`: mở cả 11643 và 11644.
- README: mô tả hai origin và cách dùng với LAN/tunnel.

### Lưu ý khi chạy thật
- Mở **cả hai cổng** trong firewall/tunnel. Nếu truy cập từ xa mà không đặt `PROXY_ORIGIN`, shell sẽ trỏ tới host:11644 và không kết nối được.
- Chưa kiểm tra trên trình duyệt thật (chỉ kiểm tra bằng HTTP/WebSocket). Nên thử: mở trang, tab mới, cookie, in, tải xuống.

## Đợt 6: lỗi 502 "fetch failed" khi tải trang qua proxy

27. **Không có fallback khi lỗi tầng kết nối**: nếu request đầu tiên tới upstream thất bại ở tầng kết nối (TLS bị reset, socket đóng, timeout), proxy trả 502 ngay mà không thử transport khác. Nay với GET/HEAD, proxy thử HTTP/2 rồi curl (cả hai vẫn đi qua kiểm tra IP). POST không được retry.
28. **Thông báo lỗi mơ hồ**: "fetch failed" nay kèm mã lỗi gốc, ví dụ `(UND_ERR_SOCKET)`, `(ECONNRESET)`, `(ESSRFBLOCKED)`, để chẩn đoán được nguyên nhân.

Lưu ý: không tái hiện được lỗi trên máy kiểm thử (link CrazyGames trả 200). Nếu vẫn lỗi, mã trong thông báo sẽ cho biết nguyên nhân.
