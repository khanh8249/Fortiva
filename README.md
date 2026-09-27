# Fortiva

> iOS sideload tool written in Rust — sign and install IPAs on iPhone without jailbreak, runs on Termux/Android.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/khanh8249/Fortiva/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20android-green)](https://github.com/khanh8249/Fortiva#requirements)

## Features

- 🔐 **Apple ID Login** — Apple's SRP-6a variant + GSA + 2FA trusted device
- ✍️ **IPA Signing** — uses the `apple-codesign` crate, auto-chains WWDR G3 + Root CA
- 📦 **Install via AFC** — no IPA repackaging, avoids the `0xe8008017` error
- 🧩 **Extension support** — signs in correct bottom-up order
- 🎯 **Special apps** — SideStore, AltStore, LiveContainer, StikStore
- 🔑 **Auto cert** — creates a new cert when switching accounts (avoids `0xe8008015`)
- 🌐 **Cross-platform** — Linux, Android (Termux)

## Requirements

Rust 1.75+, `openssl-dev`, `pkg-config`.

**Termux:**

```bash
pkg install rust clang make pkg-config openssl-dev perl
```

**Ubuntu/Debian:**

```bash
sudo apt install build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installation

```bash
git clone https://github.com/khanh8249/Fortiva.git
cd Fortiva
cargo build --release
./target/release/fortiva
```

Or download a prebuilt binary from GitHub Actions artifacts.

## Usage

```bash
./fortiva
```

### Setup: Linux & Android

**Required prerequisites for running the tool.**

For Termux:

```bash
pkg update && pkg upgrade -y && pkg install usbmuxd libimobiledevice -y
```

For Linux:

```bash
apt-get update && apt-get install usbmuxd libimobiledevice6 libimobiledevice-utils -y
```

### Main Menu

```
1. Login Apple ID
2. Test anisette server
3. Test create CSR
4. Sideload IPA (sign only)
5. Sign + Auto Install (iLoader mode)
6. Setup SideStore pairing file
...
10. Logout
0. Exit
```

## Workflow

### Method 1: Auto sign + install (recommended)

1. Menu 1 — Login Apple ID (tool automatically fetches session + 2FA)
2. Menu 5 — Enter the IPA path
3. The tool automatically:
   - Creates a cert via the Apple Developer API (or uses an existing cert)
   - Registers App IDs (main + extension)
   - Downloads provisioning profiles
   - Signs using apple-codesign
   - Installs to iPhone via AFC

### Method 2: Sign separately, then install

1. Prepare cert.pem, key.pem, profile.mobileprovision
2. Menu 4 — Sign IPA
3. Menu 5 — Install the signed .app to iPhone

### Method 3: Setup SideStore pairing file

1. Install SideStore on iPhone
2. Plug the iPhone into a computer/Android device (via USB)
3. Menu 6 — Tool automatically writes the pairing file into SideStore
4. Open SideStore, sideload without a Mac

> **iOS version support for Method 3:**
>
> | iOS version | Lockdown pairing | RPPairing | Status |
> |---|---|---|---|
> | 16.x | ✅ | Not needed | **Full support** |
> | 17.0–17.3 | ✅ | Not needed | **Full support** |
> | 17.4+ | ⚠️ Partial | ❌ Not yet | **In development** |
> | 18.x | ⚠️ Partial | ❌ Not yet | **In development** |
>
> If you're on iOS 17.4+, use `idevice_pair` on a PC for now.

## Development Tools

### main.py — Rust Syntax Analyzer

A Python tool (standard library only, no `pip install` needed) for quickly debugging Rust syntax before building.

**Usage:**

```bash
python3 main.py ./src                      # Scan the whole directory (recursive)
python3 main.py a.rs b.rs                  # Scan specific files
python3 main.py ./src --json report.json   # Export a JSON report
python3 main.py ./src --verbose            # Print details for each file
python3 main.py ./src --workers 8          # Run in parallel with 8 threads
```

**Detects:**

- Basic syntax errors (unmatched braces `{} () []` / quotes)
- Statistics: number of files, lines of code, functions, structs, enums, impls, modules, uses
- Exports a JSON report for CI integration

**Example output:**

```
Files scanned            : 54
Files with syntax errors : 0
Total lines              : 7875
Functions (fn)           : 244
Structs                  : 27
Impl blocks              : 33
```

Very useful — catches syntax errors in 1 second without waiting for `cargo check`.

## Architecture

```
src/
├── main.rs                # CLI menu, command handlers
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

## Credits

This project references:

- [apple-codesign](https://github.com/indygreg/apple-platform-rs) (indygreg) — main Rust crate for signing
- [apple-platform-rs fork](https://github.com/khanh8249/apple-platform-rs) — the fork used in Fortiva
- [Sideloader](https://github.com/Dadoum/Sideloader) (Dadoum) — D tool, reference
- [Provision](https://github.com/Dadoum/Provision) (Dadoum) — anisette + libprovision
- [auth-reference](https://github.com/khanh8249/sidedroid) — GSA protocol
- [zsign](https://github.com/zhlynn/zsign) (zhlynn) — C++ code signing reference
- [idevice](https://github.com/jkcoxson/idevice) (jkcoxson) — pure Rust device communication
- [libimobiledevice](https://libimobiledevice.org/) — cross-platform iOS library

## License

Fortiva is released under the GNU General Public License v3.0 (GPL-3.0).

This is 100% open-source software:

- ✅ No encryption, no obfuscation
- ✅ Source publicly available on GitHub
- ✅ Can be forked, modified, redistributed (provided GPL v3 is retained)
- ✅ The main.py tool is also open — developers can debug

See [LICENSE](https://github.com/khanh8249/Fortiva/blob/main/LICENSE) for details.

## Disclaimer

For personal, educational, and application-development purposes only.

Not for commercial use or in violation of Apple's Terms of Service.

## Contributing

Pull requests welcome! If you find a bug, open an Issue.

Before pushing, run:

```bash
python3 main.py ./src      # Verify syntax is clean
cargo check --release      # Verify the build is clean
```
