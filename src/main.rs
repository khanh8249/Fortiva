// src/main.rs
use anyhow::{anyhow, Context, Result};
use fortiva::auth::anisette::AnisetteClient;
use fortiva::auth::gsa::GsaClient;
use fortiva::auth::twofa::TwoFAHandler;
use fortiva::auth::AuthResult;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;

// ============================================================
//  CLI INPUT HELPERS
// ============================================================

fn prompt_text(label: &str) -> String {
    print!("{}", label);
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).expect("read line");
    s.trim().to_string()
}

fn prompt_password(label: &str) -> String {
    rpassword::prompt_password(label).unwrap_or_default()
}

fn prompt_yn(label: &str) -> bool {
    print!("{}", label);
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_lowercase() == "y"
}

fn pause() {
    print!("\nNhấn Enter để tiếp tục...");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
}

fn shellexpand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    s.to_string()
}

fn prompt_choice() -> String {
    println!();
    println!("╔══════════════════════════════════════════╗");
    println!("║           FORTIVA - MAIN MENU            ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  1. Login Apple ID (test auth pipeline)");
    println!("  2. Test anisette server");
    println!("  3. Test tạo CSR");
    println!("  4. Sideload IPA (sign only)");
    println!("  5. Install .app bundle (đã ký)");
    println!("  6. Setup SideStore pairing file");
    println!("  7. Thoát");
    println!();
    print!("Chọn (1-7): ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).expect("read line");
    s.trim().to_string()
}

// ============================================================
//  FEATURE 1: LOGIN APPLE ID
// ============================================================

fn cmd_login_apple_id() -> Result<()> {
    println!("\n=== LOGIN APPLE ID ===\n");

    let apple_id = prompt_text("Apple ID: ");
    if apple_id.is_empty() {
        return Err(anyhow!("Apple ID không được rỗng"));
    }

    let password = prompt_password("Password: ");
    if password.is_empty() {
        return Err(anyhow!("Password không được rỗng"));
    }

    println!("\n[auth] Khởi tạo pipeline...");

    // 1. Anisette
    let mut anisette = AnisetteClient::new(None);
    match anisette.fetch(false) {
        Ok(headers) => println!("[auth] ✅ Anisette OK, {} headers", headers.len()),
        Err(e) => {
            eprintln!("[auth] ❌ Anisette thất bại: {}", e);
            eprintln!("[auth] Server anisette có thể đang chết. Thử lại sau.");
            return Err(e);
        }
    }

    // 2. User/Device ID
    let user_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();

    // 3. GSA client
    let mut gsa = GsaClient::new(anisette, user_id.clone(), device_id.clone())?;

    // 4. 2FA handler
    let mut twofa = TwoFAHandler::new();

    // 5. SRP flow
    println!("\n[auth] Bắt đầu SRP authentication...");
    let srp = fortiva::auth::srp::SrpFlow::new();

    match srp.authenticate(&mut gsa, &mut twofa, &apple_id, &password, 0) {
        Ok(result) => {
            if result.authenticated {
                println!("\n✅ Đăng nhập thành công!");
                println!("   DSID: {}", result.dsid.as_deref().unwrap_or("(none)"));
                println!(
                    "   Token: {}",
                    result.session_token.as_deref().unwrap_or("(none)")
                );
            } else {
                println!("\n⚠️ Đăng nhập chưa hoàn tất.");
            }
        }
        Err(e) => {
            eprintln!("\n❌ SRP flow thất bại: {:#}", e);
            eprintln!("[auth] (Nếu lỗi SRP variant, cần debug thêm)");
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 2: TEST ANISETTE
// ============================================================

fn cmd_test_anisette() -> Result<()> {
    println!("\n=== TEST ANISETTE SERVER ===\n");

    let url = prompt_text("Anisette URL (Enter để dùng mặc định): ");
    let url_opt = if url.is_empty() { None } else { Some(url.as_str()) };

    let mut client = AnisetteClient::new(url_opt);

    println!("[anisette] Đang fetch headers...");
    match client.fetch(true) {
        Ok(headers) => {
            println!("[anisette] ✅ Nhận được {} headers:\n", headers.len());

            let important = [
                "X-Apple-I-MD",
                "X-Apple-I-MD-M",
                "X-Apple-I-MD-LU",
                "X-Apple-I-MD-RINFO",
                "X-Mme-Device-Id",
                "X-Apple-I-Client-Time",
                "X-MMe-Client-Info",
            ];

            for key in &important {
                if let Some(v) = headers.get(*key) {
                    let display = if v.len() > 60 {
                        format!("{}...({} chars)", &v[..60], v.len())
                    } else {
                        v.clone()
                    };
                    println!("  {}: {}", key, display);
                }
            }

            println!("\n[anisette] Test build CPD...");
            let mut device_id = uuid::Uuid::new_v4().to_string().to_uppercase();
            let mut client_info = fortiva::constants::DEFAULT_CLIENT_INFO.to_string();

            match client.build_cpd(
                "test@example.com",
                &mut device_id,
                &mut client_info,
                false,
            ) {
                Ok(cpd) => {
                    let n = cpd.as_object().map(|o| o.len()).unwrap_or(0);
                    println!("[anisette] ✅ CPD built với {} keys", n);
                }
                Err(e) => {
                    eprintln!("[anisette] ❌ Build CPD thất bại: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("[anisette] ❌ Thất bại: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 3: TEST CSR
// ============================================================

fn cmd_test_csr() -> Result<()> {
    println!("\n=== TEST TẠO CSR ===\n");

    let common_name = prompt_text("Common Name (Enter để dùng 'fortiva-test'): ");
    let cn = if common_name.is_empty() {
        "fortiva-test"
    } else {
        &common_name
    };

    println!("[csr] Đang sinh RSA key 2048-bit...");
    let rsa = openssl::rsa::Rsa::generate(2048)?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;

    println!("[csr] Đang tạo CSR với CN='{}'...", cn);

    use openssl::hash::MessageDigest;
    use openssl::x509::{X509NameBuilder, X509ReqBuilder};

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", cn)?;
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;
    req_builder.sign(&pkey, MessageDigest::sha256())?;

    let req = req_builder.build();
    let pem = req.to_pem()?;
    let pem_str = String::from_utf8(pem)?;

    println!("[csr] ✅ CSR tạo thành công:\n");
    println!("{}", pem_str);

    let key_pem = pkey.private_key_to_pem_pkcs8()?;
    println!("[csr] Private key PEM length: {} bytes", key_pem.len());

    Ok(())
}

// ============================================================
//  FEATURE 4: SIDELOAD IPA
// ============================================================

fn cmd_sideload() -> Result<()> {
    println!("\n=== SIDELOAD IPA (SIGN ONLY) ===\n");
    println!("Bạn cần có sẵn:");
    println!("  - File IPA cần ký");
    println!("  - cert.pem + key.pem (từ Apple Developer)");
    println!("  - File profile.mobileprovision");
    println!();

    let ipa_path = prompt_text("Đường dẫn IPA: ");
    if ipa_path.is_empty() {
        return Err(anyhow!("Đường dẫn IPA không được rỗng"));
    }
    let ipa = PathBuf::from(shellexpand(&ipa_path));
    if !ipa.exists() {
        return Err(anyhow!("IPA không tồn tại: {}", ipa.display()));
    }

    let cert_path = prompt_text("Đường dẫn cert.pem: ");
    let cert = PathBuf::from(shellexpand(&cert_path));
    if !cert.exists() {
        return Err(anyhow!("cert.pem không tồn tại: {}", cert.display()));
    }

    let key_path = prompt_text("Đường dẫn key.pem: ");
    let key = PathBuf::from(shellexpand(&key_path));
    if !key.exists() {
        return Err(anyhow!("key.pem không tồn tại: {}", key.display()));
    }

    let profile_path = prompt_text("Đường dẫn profile.mobileprovision: ");
    let profile = PathBuf::from(shellexpand(&profile_path));
    if !profile.exists() {
        return Err(anyhow!(
            "profile.mobileprovision không tồn tại: {}",
            profile.display()
        ));
    }

    // Setup
    let anisette = AnisetteClient::new(None);
    let dev = fortiva::dev::DeveloperClient::new(
        "signonly".to_string(),
        "signonly".to_string(),
    )?;

    let work_dir = std::env::temp_dir().join("fortiva");
    std::fs::create_dir_all(&work_dir)?;

    let mut sideloader = fortiva::sideload::Sideloader::new(dev, anisette, work_dir);

    println!("\n[sideload] Bắt đầu ký...");
    let signed_path = sideloader.sign_ipa(&ipa, &cert, &key, &profile)?;

    println!("\n[sideload] ✅ IPA đã ký.");
    println!("[sideload] App bundle: {}", signed_path.display());
    println!("[sideload] Có thể dùng menu 5 để cài lên iPhone.");

    Ok(())
}

// ============================================================
//  FEATURE 5: INSTALL .APP BUNDLE
// ============================================================

fn cmd_install_app() -> Result<()> {
    println!("\n=== INSTALL APP BUNDLE ===\n");
    println!("Nhập đường dẫn tới .app bundle đã ký");
    println!("(hoặc thư mục Payload/.../*.app)");
    println!();

    let app_path = prompt_text("Đường dẫn .app: ");
    if app_path.is_empty() {
        return Err(anyhow!("Đường dẫn không được rỗng"));
    }
    let path = PathBuf::from(shellexpand(&app_path));
    if !path.exists() {
        return Err(anyhow!("Path không tồn tại: {}", path.display()));
    }
    if !path.is_dir() {
        return Err(anyhow!("Path phải là thư mục: {}", path.display()));
    }

    println!("\n[install] Detect thiết bị iOS...");
    let device = fortiva::install::detect_device()?;
    println!("[install] ✅ UDID: {}", device.udid);

    println!("\n[install] Chuẩn bị runtime...");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Tạo tokio runtime thất bại")?;

    rt.block_on(async {
        use idevice::provider::UsbmuxdProvider;
        use idevice::usbmuxd::UsbmuxdAddr;

        println!("[install] Kết nối usbmuxd provider...");
        let provider = UsbmuxdProvider::new(UsbmuxdAddr::default())
            .await
            .context("Tạo usbmuxd provider thất bại")?;

        println!("[install] Bắt đầu upload + install...\n");

        fortiva::install::install_app(&provider, &path, |pct| {
            print!("\r[install] Progress: {:3}%", pct);
            io::stdout().flush().ok();
        })
        .await?;

        println!();
        Ok::<_, anyhow::Error>(())
    })?;

    println!("\n[install] ✅ Cài đặt thành công!");
    Ok(())
}

// ============================================================
//  FEATURE 6: SETUP SIDESTORE PAIRING
// ============================================================

fn cmd_setup_sidestore_pairing() -> Result<()> {
    println!("\n=== SETUP SIDESTORE PAIRING ===\n");
    println!("Tool này tự viết pairing file vào container của SideStore");
    println!("để SideStore sideload không cần Mac.\n");
    println!("Yêu cầu:");
    println!("  - iPhone đã cài SideStore");
    println!("  - Đã pair ít nhất 1 lần (idevicepair pair)");
    println!("  - usbmuxd đang chạy");
    println!();

    // Kiểm tra pairing record
    let records = fortiva::tools::list_pairing_records();
    if records.is_empty() {
        println!("⚠️  Không tìm thấy pairing record nào.");
        println!("Hãy chạy: idevicepair pair");
        println!();
        if !prompt_yn("Tiếp tục? (y/n): ") {
            return Ok(());
        }
    } else {
        println!("✅ Tìm thấy {} pairing record(s):", records.len());
        for r in &records {
            println!("   - {}", r.display());
        }
        println!();
        if !prompt_yn("Tiếp tục? (y/n): ") {
            println!("Hủy.");
            return Ok(());
        }
    }

    // Notify callback
    let notify = |msg: &str| -> Result<bool> {
        println!("\n⚠️  {}", msg);
        Ok(prompt_yn("Tiếp tục? (y/n): "))
    };

    // Chạy async
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Tạo tokio runtime thất bại")?;

    rt.block_on(async {
        fortiva::tools::setup_sidestore_pairing(notify).await
    })?;

    println!("\n[sidestore] ✅ Hoàn tất!");
    Ok(())
}

// ============================================================
//  MAIN LOOP
// ============================================================

fn main() {
    // Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    println!();
    println!("╔══════════════════════════════════════════╗");
    println!("║              F O R T I V A               ║");
    println!("║     iOS Sideload Tool (Rust port)        ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    loop {
        let choice = prompt_choice();

        let result = match choice.as_str() {
            "1" => cmd_login_apple_id(),
            "2" => cmd_test_anisette(),
            "3" => cmd_test_csr(),
            "4" => cmd_sideload(),
            "5" => cmd_install_app(),
            "6" => cmd_setup_sidestore_pairing(),
            "7" => {
                println!("\nTạm biệt.");
                return;
            }
            _ => {
                eprintln!("\n❌ Lựa chọn không hợp lệ: {}", choice);
                continue;
            }
        };

        if let Err(e) = result {
            eprintln!("\n❌ Lỗi: {:#}", e);
            let mut source = e.source();
            while let Some(s) = source {
                eprintln!("   ↳ {}", s);
                source = s.source();
            }
        }

        pause();
    }
}