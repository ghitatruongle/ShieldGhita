# Shield Ghita

**Shield Ghita** là ứng dụng bảo vệ mạng và chặn quảng cáo toàn diện dành cho máy tính (Windows), được xây dựng bằng **Rust** và giao diện **Slint UI** hiện đại, siêu nhẹ và tối ưu hiệu năng cao.

---

## ✨ Tính năng nổi bật

### 1. Chặn quảng cáo đa nền tảng (System-wide Adblocker)
- **Chặn quảng cáo toàn diện**: Loại bỏ triệt để quảng cáo video, âm thanh, banner, pop-up và theo dõi người dùng trên mọi nền tảng:
  - **Video & Livestream**: YouTube, Twitch, TikTok, Facebook Video...
  - **Âm nhạc & Streaming**: Spotify, SoundCloud, Zing MP3, Nhaccuatui...
  - **Trình duyệt & Ứng dụng**: Chrome, Edge, Firefox, Brave và tất cả các phần mềm chạy trên máy.
- **Hỗ trợ song song IPv4 & IPv6**: Trả về `0.0.0.0` (Type A) và `::` (Type AAAA) giúp ngắt kết nối quảng cáo tức thì mà không làm treo các kết nối HTTPS.
- **Tích hợp bộ lọc hàng đầu thế giới**: Hỗ trợ AdGuard DNS Filter, OISD, StevenBlack Hosts, Anudeep Adservers cùng tính năng tự động cập nhật định kỳ.

### 2. Tăng tốc mạng với Parallel DNS Racing
- **Đua truy vấn song song (Parallel Racing)**: Gửi truy vấn đồng thời tới các upstream DoH uy tín (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`), tự động lấy phản hồi từ máy chủ nhanh nhất.
- **Bộ nhớ đệm siêu tốc (In-Memory DNS Cache)**: Phân giải các tên miền thường dùng trong thời gian dưới `0.1ms`.

### 3. Quét & Phân tích thiết bị mạng cục bộ (LAN Scanner)
- Tự động quét và phát hiện tất cả các thiết bị đang kết nối cùng mạng Wi-Fi/Ethernet nội bộ.
- Hiển thị chi tiết địa chỉ IP, địa chỉ MAC, nhà sản xuất (Vendor/OUI), độ trễ (Ping latency) và các cổng dịch vụ đang mở (HTTP, HTTPS, SSH, SMB...).

### 4. Giám sát kết nối & Lưu lượng thời gian thực (Traffic Monitor)
- Thống kê chi tiết băng thông mạng Tải về (Download) và Tải lên (Upload).
- Theo dõi toàn bộ các kết nối mạng đang hoạt động theo từng tiến trình (PID, Process Name, Protocol, Local/Remote IP & Port).

### 5. Khóa mạng khẩn cấp & Cơ chế tự bảo vệ an toàn
- **Master Internet Lock**: Khóa toàn bộ truy cập Internet ra bên ngoài chỉ với một click khi phát hiện nguy cơ bảo mật.
- **Khôi phục DNS thông minh 100%**: Tự động sao lưu và hoàn nguyên cấu hình DNS gốc (DHCP hoặc IP tĩnh) của máy khi đóng app hoặc khi gặp sự cố, đảm bảo máy tính không bao giờ bị mất mạng.
- **Chạy ngầm hoàn toàn êm ái (Stealth Execution)**: Loại bỏ triệt để các cửa sổ console đen nhấp nháy khi app chạy nền.

---

## Hướng dẫn cài đặt & Sử dụng

### 1. Cài đặt nhanh qua bộ Setup
- Tải tệp cài đặt `ShieldGhita_Setup_v0.0.0+0.exe` và chạy với quyền **Administrator**.
- Làm theo hướng dẫn trên màn hình cài đặt để hoàn tất.

### 2. Chạy từ mã nguồn (Dành cho Developer)
Yêu cầu đã cài đặt **Rust** (Cargo) và chạy Terminal với quyền **Administrator**:

```bash
# Kiểm tra mã nguồn
cargo check

# Chạy kiểm thử tự động
cargo test

# Chạy ứng dụng
cargo run --release
```

---

## ⚠️ Cảnh báo & Miễn trừ trách nhiệm (Disclaimer)

> [!CAUTION]
> **QUAN TRỌNG: VUI LÒNG ĐỌC KỸ TRƯỚC KHI SỬ DỤNG**
>
> 1. **Mục đích nghiên cứu**: Dự án này được phát triển hoàn toàn vì mục đích **học tập, nghiên cứu kỹ thuật mạng và bảo mật cá nhân**.
> 2. **Miễn trừ trách nhiệm kỹ thuật**: Tác giả và những người đóng góp **không chịu bất kỳ trách nhiệm nào** đối với mọi sự cố hệ thống, hỏng hóc phần cứng/phần mềm, gián đoạn kết nối hoặc mất mát dữ liệu phát sinh trong quá trình sử dụng phần mềm này. Người dùng tự chịu mọi rủi ro khi cài đặt và sử dụng.
> 3. **Miễn trừ trách nhiệm pháp lý**: Nghiêm cấm tuyệt đối việc sử dụng phần mềm hoặc bất kỳ phần mã nguồn nào vào các mục đích bất hợp pháp, phá hoại hệ thống mạng, tấn công mạng hoặc vi phạm pháp luật hiện hành. Tác giả hoàn toàn không chịu trách nhiệm đối với bất kỳ hành vi sai trái hoặc lạm dụng nào từ phía người sử dụng.
