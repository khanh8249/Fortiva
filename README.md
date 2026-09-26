# Fortiva

> iOS sideload tool written in Rust — ký và cài IPA lên iPhone không cần jailbreak, chạy trên Termux/Android.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/khanh8249/Fortiva/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20android-green)](https://github.com/khanh8249/Fortiva#yêu-cầu)
## Tính năng

- 🔐 **Login Apple ID** — SRP-6a variant Apple + GSA + 2FA trusted device
- ✍️ **Ký IPA** — dùng crate `apple-codesign`, tự động chain WWDR G3 + Root CA
- 📦 **Cài qua AFC** — không đóng gói lại IPA, tránh lỗi `0xe8008017`
- 🧩 **Hỗ trợ extension** — ký đúng thứ tự bottom-up
- 🎯 **Special apps** — SideStore, AltStore, LiveContainer, StikStore
- 🔑 **Auto cert** — tự tạo cert mới khi đổi account (không bị `0xe8008015`)
- 🌐 **Cross-platform** — Linux, Android (Termux)

## Yêu cầu

Rust 1.75+, `openssl-dev`, `pkg-config`.

**Termux:**

```bash
pkg install rust clang make pkg-config openssl-dev perl
```

Ubuntu/Debian:

```bash
sudo apt install build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Cài đặt

```bash
git clone https://github.com/khanh8249/Fortiva.git
cd Fortiva
cargo build --release
./target/release/fortiva
```

Hoặc tải prebuilt binary từ GitHub Actions artifacts.

Sử dụng

```bash
./fortiva
```
**Setup:linux-android**
**yêu cầu bắt buộc khi chạy tool**
dành cho termux
```bash
pkg update && pkg upgrade -y && pkg install usbmuxd libimobiledevice -y
```
Dành cho linux
```bash
apt-get update && apt-get install usbmuxd libimobiledevice6 libimobiledevice-utils -y
```
Menu chính:

```
1. Login Apple ID
2. Test anisette server
3. Test tạo CSR
4. Sideload IPA (sign only)
5. Sign + Auto Install (iLoader mode)
6. Setup SideStore pairing file
...
10. Logout
0. Thoát
```

Workflow

Cách 1: Auto sign + install (khuyên dùng)

1. Menu 1 — Login Apple ID (tool tự lấy session + 2FA)
2. Menu 5 — Nhập đường dẫn IPA
3. Tool tự động:
   · Tạo cert qua Apple Developer API (hoặc dùng cert đã có)
   · Register App IDs (main + extension)
   · Download provisioning profiles
   · Sign bằng apple-codesign
   · Cài lên iPhone qua AFC

Cách 2: Sign riêng rồi install

1. Chuẩn bị cert.pem, key.pem, profile.mobileprovision
2. Menu 4 — Sign IPA
3. Menu 5 — Install .app đã ký lên iPhone

Cách 3: Setup SideStore pairing file

1. Cài SideStore trên iPhone
2. Cắm iPhone vào máy tính/Android (qua USB)
3. Menu 6 — Tool tự ghi pairing file vào SideStore
4. Mở SideStore, sideload không cần Mac

🛠️ Development Tools

main.py — Rust Syntax Analyzer

Tool Python (chỉ dùng thư viện chuẩn, không cần pip install) để debug nhanh syntax Rust trước khi build.

Cách dùng:

```bash
python3 main.py ./src                      # Quét cả thư mục (đệ quy)
python3 main.py a.rs b.rs                  # Quét từng file cụ thể
python3 main.py ./src --json report.json   # Xuất báo cáo JSON
python3 main.py ./src --verbose            # In chi tiết từng file
python3 main.py ./src --workers 8          # Chạy song song 8 luồng
```

Phát hiện:

· Lỗi cú pháp cơ bản (ngoặc {} () [] / dấu nháy không khớp)
· Thống kê: số file, dòng code, hàm, struct, enum, impl, module, use
· Xuất JSON report cho CI integration

Ví dụ output:

```
Số file đã quét      : 54
File có lỗi cú pháp  : 0
Tổng số dòng         : 7875
Hàm (fn)             : 244
Struct               : 27
Impl blocks          : 33
```

Rất hữu ích — catch syntax errors trong 1 giây, không cần đợi cargo check.

Architecture

```
src/
├── main.rs                # Menu CLI, cmd handlers
├── auth/                  # SRP + GSA + Anisette
├── dev/                   # Apple Developer API
│   ├── certificate.rs     # create/ensure cert
│   ├── app_ids.rs         # register App IDs
│   ├── app_groups.rs      # App Group management
│   └── devices.rs         # UDID registration
├── sideload/
│   ├── signer.rs          # apple-codesign wrapper
│   ├── application.rs     # IPA parser
│   └── install_full.rs    # full flow
├── session/               # Session storage
└── usb/                   # usbmuxd + idevice
```

Credits

Dự án tham khảo từ:

· - [apple-codesign](https://github.com/indygreg/apple-platform-rs) (indygreg) — Rust crate chính cho việc ký
· - [apple-platform-rs fork](https://github.com/khanh8249/apple-platform-rs) — fork dùng trong Fortiva
· - [Sideloader](https://github.com/Dadoum/Sideloader) (Dadoum) — tool D, reference
· - [Provision](https://github.com/Dadoum/Provision) (Dadoum) — anisette + libprovision
· - [auth-reference](https://github.com/khanh8249/sidedroid) — GSA protocol 
· - [zsign](https://github.com/zhlynn/zsign) (zhlynn) — C++ code signing reference
· - [idevice](https://github.com/jkcoxson/idevice) (jkcoxson) — pure Rust device communication
· - [libimobiledevice](https://libimobiledevice.org/) — cross-platform iOS library

License

Fortiva được phát hành dưới GNU General Public License v3.0 (GPL-3.0).

Đây là phần mềm mã nguồn mở 100%:

· ✅ Không encrypt, không obfuscate
· ✅ Source công khai trên GitHub
· ✅ Có thể fork, sửa, phân phối lại (với điều kiện giữ GPL v3)
· ✅ Tool main.py cũng mở — developer có thể debug

Xem [LICENSE](https://github.com/khanh8249/Fortiva/blob/main/LICENSE) để biết chi tiết.

Disclaimer

Chỉ dùng cho mục đích cá nhân, học tập, phát triển ứng dụng.

Không dùng cho mục đích thương mại hoặc vi phạm điều khoản dịch vụ của Apple.

Đóng góp

Pull requests welcome! Nếu có bug, mở Issue.

Trước khi push, chạy:

```bash
python3 main.py ./src      # Verify syntax sạch
cargo check --release      # Verify build sạch
```
