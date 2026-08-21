# Shield Ghita

<div align="center">

**Master Internet Controller & Ultra-Fast Network Security Shield for Windows**

[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://github.com/ghitatruongle/ShieldGhita)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg)](https://microsoft.com)

[🇬🇧 English](#-english) &nbsp; | &nbsp; [🇻🇳 Tiếng Việt](#-tiếng-việt)

</div>

---

# 🇬🇧 English

**Shield Ghita** is a comprehensive, ultra-lightweight Windows network security controller and system-wide adblocker built with **Rust** and a modern **Slint UI** interface for peak performance, ultra-low resource usage, and rock-solid stability.

---

## Key Features

### 1. System-Wide Ad & Tracker Blocker
- **Comprehensive Ad Blocking**: Eliminates intrusive video ads, audio ads, banners, pop-ups, and trackers across all platforms:
  - **Video & Livestream**: YouTube, Twitch, TikTok, Facebook Video, etc.
  - **Music & Streaming**: Spotify, SoundCloud, Zing MP3, etc.
  - **Browsers & Desktop Apps**: Chrome, Edge, Firefox, Brave, and all native Windows applications.
- **Dual-Stack IPv4 & IPv6 Support**: Returns `0.0.0.0` (Type A) and `::` (Type AAAA) for immediate connection dropping without breaking HTTPS handshake lifecycles.
- **World-Class Threat Feeds**: Integrated with AdGuard DNS Filter, OISD, StevenBlack Hosts, and Anudeep Adservers with scheduled automatic updates.
- **Real-Time In-App Toast Notifications**: Instant, smooth floating alerts whenever an ad or malicious tracker is intercepted.

### 2. Low-Latency Parallel DNS Racing & Memory Cache
- **Parallel Racing Engine**: Dispatches concurrent upstream queries to trusted DoH endpoints (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`), automatically adopting the fastest response.
- **Ultra-Fast In-Memory DNS Cache**: Delivers sub-`0.1ms` resolution times for frequently requested domain queries.

### 3. Active Local Area Network (LAN) Scanner
- **Active Layer 2 ARP Subnet Sweep**: Concurrently scans all 254 IP addresses across the local `/24` subnet using fast native `SendARP` Win32 API.
- **Detailed Hardware & Service Discovery**: Inspects IP address, MAC address, Hardware Manufacturer (OUI/Vendor), ICMP ping latency, NetBIOS hostnames, and open service ports (CCTV Camera, Smart TV, Mobile Phone, PC/Laptop, IoT).

### 4. Real-time Traffic & Connection Inspector
- Live upload and download bandwidth throughput metrics read directly from kernel counters.
- Comprehensive active socket inspector tracking processes (PID, Process Name, Protocol, Local and Remote IP/Port tuples).

### 5. Master Internet Lock & Fail-Safe DNS Restoration
- **Master Internet Lock**: Instantly isolate and block all outbound internet traffic with one click during security incidents.
- **100% Fail-Safe DNS Restoration**: Backs up and automatically restores original network DNS settings (DHCP or Static) upon graceful shutdown or crash recovery.
- **Stealth Background Execution**: Zero black console window flashes or flickering during startup and background operation.

### 6. Settings & Multi-Language Support
- In-app dynamic language switching between **English 🇬🇧** and **Tiếng Việt 🇻🇳**.
- Configurable settings for Windows autostart, minimize to tray, ad-blocking notifications, and custom filter rules.

---

## Installation & Getting Started

### 1. Pre-built Setup Installer
- Download `ShieldGhita_Setup_v0.0.1.exe` and execute with **Administrator** privileges.
- The installer automatically terminates running instances, cleanly uninstalls previous versions, and deploys the new release safely.

### 2. Build From Source (For Developers)
Requires **Rust** (Cargo toolchain) and an elevated **Administrator** terminal:

```bash
# Check source code integrity
cargo check

# Run automated test suites
cargo test

# Launch release binary
cargo run --release
```

---

## Security & Legal Disclaimer

> [!CAUTION]
> **PLEASE READ CAREFULLY BEFORE USING THIS SOFTWARE**
>
> 1. **Educational & Research Purpose**: This project is developed solely for **learning, networking research, and personal cybersecurity experimentation**.
> 2. **Technical Disclaimer**: The authors and contributors **assume no liability or responsibility** for any system failure, hardware/software damage, network interruption, or data loss resulting from the use of this software. You use this application at your own risk.
> 3. **Legal Disclaimer**: Any unlawful usage, unauthorized network exploitation, cyber attacks, or violation of applicable local/international regulations using this tool or its source code is strictly prohibited. The authors bear no responsibility for any misconduct or misuse by end users.

---

# 🇻🇳 Tiếng Việt

**Shield Ghita** là ứng dụng bảo vệ mạng và chặn quảng cáo toàn diện dành cho máy tính (Windows), được xây dựng bằng **Rust** và giao diện **Slint UI** hiện đại, siêu nhẹ, tiết kiệm tài nguyên và bảo vệ quyền riêng tư người dùng.

---

## Tính năng nổi bật

### 1. Chặn quảng cáo đa nền tảng (System-wide Adblocker)
- **Chặn quảng cáo toàn diện**: Loại bỏ triệt để quảng cáo video, âm thanh, banner, pop-up và theo dõi người dùng trên mọi nền tảng:
  - **Video & Livestream**: YouTube, Twitch, TikTok, Facebook Video...
  - **Âm nhạc & Streaming**: Spotify, SoundCloud, Zing MP3, Nhaccuatui...
  - **Trình duyệt & Ứng dụng**: Chrome, Edge, Firefox, Brave và tất cả các phần mềm chạy trên máy.
- **Hỗ trợ song song IPv4 & IPv6**: Trả về `0.0.0.0` (Type A) và `::` (Type AAAA) giúp ngắt kết nối quảng cáo tức thì mà không làm treo các kết nối HTTPS.
- **Tích hợp bộ lọc hàng đầu thế giới**: Hỗ trợ AdGuard DNS Filter, OISD, StevenBlack Hosts, Anudeep Adservers cùng tính năng tự động cập nhật định kỳ.
- **Thông báo chặn thời gian thực**: Hiển thị Toast thông báo nổi trực quan ngay khi phát hiện và chặn quảng cáo/mã theo dõi ngầm.

### 2. Tăng tốc mạng với Parallel DNS Racing
- **Đua truy vấn song song (Parallel Racing)**: Gửi truy vấn đồng thời tới các upstream DoH uy tín (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`), tự động lấy phản hồi từ máy chủ nhanh nhất.
- **Bộ nhớ đệm siêu tốc (In-Memory DNS Cache)**: Phân giải các tên miền thường dùng trong thời gian dưới `0.1ms`.

### 3. Quét chủ động thiết bị mạng LAN (Active LAN Scanner)
- **Quét toàn bộ dải mạng /24**: Sử dụng `SendARP` Win32 API quét đồng thời 254 IP trong mạng nội bộ, khắc phục hoàn toàn tình trạng thiếu thiết bị của bảng ARP thụ động.
- **Nhận diện thiết bị thông minh**: Hiển thị chi tiết IP, MAC, nhà sản xuất (Vendor/OUI), độ trễ (Ping latency), tên NetBIOS và phân loại Camera, Smart TV, Điện thoại, Máy tính, IoT.

### 4. Giám sát kết nối & Lưu lượng thời gian thực (Traffic Monitor)
- Thống kê chi tiết băng thông Tải về (Download) và Tải lên (Upload) trực tiếp từ Kernel không gây tốn CPU.
- Theo dõi toàn bộ các kết nối mạng đang hoạt động theo từng tiến trình (PID, Process Name, Protocol, Local/Remote IP & Port).

### 5. Khóa mạng khẩn cấp & Cơ chế hoàn nguyên DNS an toàn 100%
- **Master Internet Lock**: Khóa toàn bộ truy cập Internet ra bên ngoài chỉ với một click khi phát hiện nguy cơ bảo mật.
- **Khôi phục DNS thông minh 100%**: Tự động sao lưu và hoàn nguyên cấu hình DNS gốc (DHCP hoặc IP tĩnh) của máy khi đóng app hoặc khi gặp sự cố, đảm bảo máy tính không bao giờ bị mất mạng.
- **Chạy ngầm hoàn toàn êm ái (Stealth Execution)**: Loại bỏ triệt để các cửa sổ console đen nhấp nháy khi app chạy nền.

### 6. Cài đặt & Chuyển đổi ngôn ngữ Tiếng Anh / Tiếng Việt
- Tích hợp tab Cài đặt trong app giúp chuyển đổi linh hoạt giữa **Tiếng Việt 🇻🇳** và **Tiếng Anh 🇬🇧**.
- Tùy chỉnh tự khởi động cùng Windows, thu nhỏ xuống khay hệ thống, bật/tắt thông báo chặn quảng cáo.

---

## Hướng dẫn cài đặt & Sử dụng

### 1. Cài đặt nhanh qua bộ Setup
- Tải tệp cài đặt `ShieldGhita_Setup_v0.0.1.exe` và chạy với quyền **Administrator**.
- Trình cài đặt sẽ tự động dừng ứng dụng cũ, dọn sạch phiên bản trước và cập nhật phiên bản mới một cách an toàn.

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

## Cảnh báo & Miễn trừ trách nhiệm (Disclaimer)

> [!CAUTION]
> **QUAN TRỌNG: VUI LÒNG ĐỌC KỸ TRƯỚC KHI SỬ DỤNG**
>
> 1. **Mục đích nghiên cứu**: Dự án này được phát triển hoàn toàn vì mục đích **học tập, nghiên cứu kỹ thuật mạng và bảo mật cá nhân**.
> 2. **Miễn trừ trách nhiệm kỹ thuật**: Tác giả và những người đóng góp **không chịu bất kỳ trách nhiệm nào** đối với mọi sự cố hệ thống, hỏng hóc phần cứng/phần mềm, gián đoạn kết nối hoặc mất mát dữ liệu phát sinh trong quá trình sử dụng phần mềm này. Người dùng tự chịu mọi rủi ro khi cài đặt và sử dụng.
> 3. **Miễn trừ trách nhiệm pháp lý**: Nghiêm cấm tuyệt đối việc sử dụng phần mềm hoặc bất kỳ phần mã nguồn nào vào các mục đích bất hợp pháp, phá hoại hệ thống mạng, tấn công mạng hoặc vi phạm pháp luật hiện hành. Tác giả hoàn toàn không chịu trách nhiệm đối với bất kỳ hành vi sai trái hoặc lạm dụng nào từ phía người sử dụng.


