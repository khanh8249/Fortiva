# Fortiva

> iOS sideload tool written in Rust — ký và cài IPA lên iPhone không cần jailbreak.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20android-green)]()

## Tính năng

- Login Apple ID (SRP-6a variant Apple + GSA + 2FA)
- Ký IPA dùng crate `apple_codesign`, tự động chain WWDR G3 + Root CA
- Cài qua AFC, không đóng gói lại IPA, tránh lỗi `0xe8008017`
- Hỗ trợ extension, ký đúng thứ tự
- Special apps: SideStore, AltStore, LiveContainer, StikStore
- App Group + Increased Memory Limit cho LiveContainer
- SideStore pairing file setup
- Cross-platform: Linux, macOS, Android (Termux)

## Yêu cầu

Rust 1.75+, `openssl-dev`, `pkg-config`.

Termux:

    pkg install rust clang make pkg-config openssl-dev perl

Ubuntu/Debian:

    sudo apt install build-essential pkg-config libssl-dev
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

macOS:

    xcode-select --install
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

## Cài đặt

    git clone https://github.com/khanh8249/fortiva.git
    cd fortiva
    cargo build --release
    ./target/release/fortiva

## Sử dụng

    ./fortiva

Menu:

    1. Login Apple ID (test auth pipeline)
    2. Test anisette server
    3. Test tạo CSR
    4. Sideload IPA (sign only)
    5. Install .app bundle (đã ký)
    6. Setup SideStore pairing file
    7. Thoát

## Workflow

**Cách 1: Tự ký + cài (cần cert)**

1. Chuẩn bị `cert.pem`, `key.pem`, `profile.mobileprovision` từ Apple Developer.
2. Menu 4, nhập đường dẫn các file, ký IPA.
3. Menu 5, nhập đường dẫn `.app` đã ký, cài lên iPhone.

**Cách 2: Setup SideStore (không cần cert riêng)**

1. Cài SideStore trên iPhone trước.
2. Cắm iPhone vào máy tính hoặc Android.
3. Menu 6, tool tự ghi pairing file vào SideStore.
4. Mở SideStore, sideload không cần Mac.

## Credits

Dự án tham khảo từ:

- [apple-codesign](https://github.com/indygreg/apple-platform-rs) (indygreg) - crate Rust chính cho việc ký
- [Sideloader](https://github.com/Dadoum/Sideloader) (Dadoum) - tool D, tham khảo cấu trúc sideload
- [isideload](https://github.com/Dadoum/isideload) (Dadoum) - Rust port của Sideloader
- [pypush](https://github.com/JJTech0130/pypush) - SRP-6a variant Apple
- [libgsa](https://github.com/nythepegasus/libgsa) - GSA protocol
- [anisette-v3-server](https://github.com/Dadoum/Provision) (Dadoum) - anisette server
- [Impactor](https://github.com/khcrysalis/Impactor) (khcrysalis) - certificate handling
- [zsign](https://github.com/zhlynn/zsign) (zhlynn) - C++ code signing
- [zsign-rs](https://github.com/kanid99/zsign-rs) - Rust port của zsign
- [idevice](https://github.com/jkcoxson/idevice) (jkcoxson) - pure Rust device communication
- [libimobiledevice](https://libimobiledevice.org/) - cross-platform iOS device library
- [AltStore](https://altstore.io/) (Riley Testut) - concept sideload
- [SideStore](https://sidestore.io/) - fork AltStore với JIT-less
- [LiveContainer](https://github.com/khanhduytran0/LiveContainer) (khanhduytran0) - chạy app iOS không cài

## License

MIT License. Xem [LICENSE](LICENSE).

## Disclaimer

Chỉ dùng cho mục đích cá nhân, học tập, phát triển ứng dụng.
