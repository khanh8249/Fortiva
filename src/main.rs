// src/main.rs
use anyhow::{anyhow, Context, Result};
use fortiva::auth::anisette::AnisetteClient;
use fortiva::auth::gsa::GsaClient;
use fortiva::auth::twofa::TwoFAHandler;
use fortiva::ui::{log, menu, spinner, theme};
use std::io::{self, Write};
use std::path::PathBuf;

// ============================================================
//  CLI INPUT HELPERS (dùng read_until — không panic UTF-8)
// ============================================================

fn prompt_text(label: &str) -> String {
    print!("  {} {} ", theme::primary("»"), label);
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    io::stdin().read_until(b'\n', &mut buf).ok();
    String::from_utf8_lossy(&buf).trim().to_string()
}

fn prompt_password(label: &str) -> String {
    let prompt = format!("  {} {} ", theme::primary("»"), label);
    match rpassword::prompt_password(prompt) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("(Không ẩn được password, gõ trực tiếp)");
            prompt_text(label)
        }
    }
}

fn pause() {
    print!("\n  {} ", theme::muted("Nhấn Enter để tiếp tục..."));
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    let _ = io::stdin().read_until(b'\n', &mut buf);
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
    menu::print_menu();
    print!("  {} Chọn (1-5): ", theme::bold_primary("?"));
    io::stdout().flush().ok();
    let mut buf = Vec::new();
    io::stdin().read_until(b'\n', &mut buf).ok();
    String::from_utf8_lossy(&buf).trim().to_string()
}

// ============================================================
//  STATUS CHECK
// ============================================================

fn get_iphone_status() -> String {
    let usbmuxd_ok = std::process::Command::new("pgrep")
        .args(["-f", "usbmuxd"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !usbmuxd_ok {
        return theme::muted("🔴 DISCONNECTED (usbmuxd chưa chạy)");
    }

    match std::process::Command::new("idevice_id").arg("-l").output() {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            let udid = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if udid.len() >= 8 {
                theme::success(&format!("🟢 CONNECTED (UDID: {}...)", &udid[..8]))
            } else {
                theme::success("🟢 CONNECTED")
            }
        }
        _ => theme::muted("🔴 DISCONNECTED"),
    }
}

// ============================================================
//  FEATURE 1: LOGIN APPLE ID
// ============================================================

fn cmd_login_apple_id() -> Result<()> {
    log::header("LOGIN APPLE ID");

    let apple_id = prompt_text("Apple ID:");
    if apple_id.is_empty() {
        return Err(anyhow!("Apple ID không được rỗng"));
    }

    let password = prompt_password("Password:");
    if password.is_empty() {
        return Err(anyhow!("Password không được rỗng"));
    }

    println!();

    let sp = spinner::new("Đang lấy anisette headers...");
    let mut anisette = AnisetteClient::new(None);
    let _headers = match anisette.fetch(false) {
        Ok(h) => {
            sp.finish_and_clear();
            log::success(&format!("Anisette OK ({} headers)", h.len()));
            h
        }
        Err(e) => {
            sp.finish_and_clear();
            log::error(&format!("Anisette thất bại: {}", e));
            return Err(e);
        }
    };

    let user_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let device_id = uuid::Uuid::new_v4().to_string().to_uppercase();

    let mut gsa = GsaClient::new(anisette, user_id.clone(), device_id.clone());
    let mut twofa = TwoFAHandler::new();

    println!();
    log::info("Bắt đầu SRP authentication...");
    println!();

    let mut srp = fortiva::auth::srp::SrpFlow::new();

    match srp.authenticate(&mut gsa, &mut twofa, &apple_id, &password, 0) {
        Ok(result) => {
            println!();
            if result.authenticated {
                println!("  {}╭─────────────────────────────────────────╮{}", theme::SUCCESS, theme::RESET);
                println!("  {}│{}     {}✅ ĐĂNG NHẬP THÀNH CÔNG{}             {}│{}",
                    theme::SUCCESS, theme::RESET, theme::BOLD, theme::RESET, theme::SUCCESS, theme::RESET);
                println!("  {}├─────────────────────────────────────────┤{}", theme::SUCCESS, theme::RESET);
                println!("  {}│{}  Apple ID:  {}", theme::SUCCESS, theme::RESET, theme::muted(&apple_id));
                println!("  {}│{}  DSID:      {}", theme::SUCCESS, theme::RESET,
                    result.dsid.as_deref().unwrap_or("(none)"));
                let token_display = match &result.session_token {
                    Some(t) if t.len() > 30 => format!("{}...", &t[..30]),
                    Some(t) => t.clone(),
                    None => "(none)".to_string(),
                };
                println!("  {}│{}  Token:     {}", theme::SUCCESS, theme::RESET, token_display);
                println!("  {}╰─────────────────────────────────────────╯{}", theme::SUCCESS, theme::RESET);
            } else {
                log::warn("Đăng nhập chưa hoàn tất.");
            }
        }
        Err(e) => {
            println!();
            log::error(&format!("SRP flow thất bại: {:#}", e));
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 2: TEST ANISETTE
// ============================================================

fn cmd_test_anisette() -> Result<()> {
    log::header("TEST ANISETTE SERVER");

    let url = prompt_text("Anisette URL (Enter = mặc định):");
    let url_opt = if url.is_empty() { None } else { Some(url.as_str()) };

    println!();
    let sp = spinner::new("Đang fetch headers từ anisette server...");
    let mut client = AnisetteClient::new(url_opt);

    match client.fetch(true) {
        Ok(headers) => {
            sp.finish_and_clear();
            log::success(&format!("Nhận được {} headers", headers.len()));
            println!();

            println!("  {}┌──────────────────────────────────────────┐{}", theme::MUTED, theme::RESET);
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
                    let display = if v.len() > 50 {
                        format!("{}...({} chars)", &v[..50], v.len())
                    } else {
                        v.clone()
                    };
                    println!("  {}│{}  {:<26} {}", theme::MUTED, theme::RESET,
                        theme::primary(key), display);
                }
            }
            println!("  {}└──────────────────────────────────────────┘{}", theme::MUTED, theme::RESET);

            println!();
            let sp2 = spinner::new("Đang test build CPD...");
            let mut device_id = uuid::Uuid::new_v4().to_string().to_uppercase();
            let mut client_info = fortiva::constants::DEFAULT_CLIENT_INFO.to_string();

            match client.build_cpd("test@example.com", &mut device_id, &mut client_info, false) {
                Ok(cpd) => {
                    sp2.finish_and_clear();
                    let n = cpd.as_object().map(|o| o.len()).unwrap_or(0);
                    log::success(&format!("CPD built với {} keys", n));
                }
                Err(e) => {
                    sp2.finish_and_clear();
                    log::error(&format!("Build CPD thất bại: {}", e));
                }
            }
        }
        Err(e) => {
            sp.finish_and_clear();
            log::error(&format!("Thất bại: {}", e));
            return Err(e);
        }
    }

    Ok(())
}

// ============================================================
//  FEATURE 3: TEST CSR
// ============================================================

fn cmd_test_csr() -> Result<()> {
    log::header("TEST TẠO CSR");

    let common_name = prompt_text("Common Name (Enter = 'fortiva-test'):");
    let cn = if common_name.is_empty() {
        "fortiva-test"
    } else {
        &common_name
    };

    println!();
    let sp = spinner::new("Đang sinh RSA key 2048-bit...");
    let rsa = openssl::rsa::Rsa::generate(2048)?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa)?;

    sp.set_message("Đang tạo CSR...");
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

    sp.finish_and_clear();
    log::success(&format!("CSR tạo thành công (CN='{}')", cn));
    println!();

    println!("  {}┌──────────────────────────────────────────┐{}", theme::MUTED, theme::RESET);
    for line in pem_str.lines().take(20) {
        println!("  {}│{} {}", theme::MUTED, theme::RESET, theme::muted(line));
    }
    if pem_str.lines().count() > 20 {
        println!("  {}│{} {}", theme::MUTED, theme::RESET, theme::muted("..."));
    }
    println!("  {}└──────────────────────────────────────────┘{}", theme::MUTED, theme::RESET);

    let key_pem = pkey.private_key_to_pem_pkcs8()?;
    println!();
    log::info(&format!("Private key PEM: {} bytes", key_pem.len()));

    Ok(())
}

// ============================================================
//  FEATURE 4: SIDELOAD IPA
// ============================================================

fn cmd_sideload() -> Result<()> {
    log::header("SIDELOAD IPA (SIGN ONLY)");

    println!("  {} Bạn cần có sẵn:", theme::muted("→"));
    println!("    {} File IPA cần ký", theme::muted("•"));
    println!("    {} cert.pem + key.pem", theme::muted("•"));
    println!("    {} profile.mobileprovision", theme::muted("•"));
    println!();

    let ipa_path = prompt_text("Đường dẫn IPA:");
    if ipa_path.is_empty() {
        return Err(anyhow!("Đường dẫn IPA không được rỗng"));
    }
    let ipa = PathBuf::from(shellexpand(&ipa_path));
    if !ipa.exists() {
        return Err(anyhow!("IPA không tồn tại: {}", ipa.display()));
    }

    let cert_path = prompt_text("Đường dẫn cert.pem:");
    let cert = PathBuf::from(shellexpand(&cert_path));
    if !cert.exists() {
        return Err(anyhow!("cert.pem không tồn tại: {}", cert.display()));
    }

    let key_path = prompt_text("Đường dẫn key.pem:");
    let key = PathBuf::from(shellexpand(&key_path));
    if !key.exists() {
        return Err(anyhow!("key.pem không tồn tại: {}", key.display()));
    }

    let profile_path = prompt_text("Đường dẫn profile.mobileprovision:");
    let profile = PathBuf::from(shellexpand(&profile_path));
    if !profile.exists() {
        return Err(anyhow!(
            "profile.mobileprovision không tồn tại: {}",
            profile.display()
        ));
    }

    println!();

    let anisette = AnisetteClient::new(None);
    let dev = fortiva::dev::DeveloperClient::new(
        "signonly".to_string(),
        "signonly".to_string(),
    )?;

    let work_dir = std::env::temp_dir().join("fortiva");
    std::fs::create_dir_all(&work_dir)?;

    let mut sideloader = fortiva::sideload::Sideloader::new(dev, anisette, work_dir);

    log::info("Bắt đầu ký IPA...");
    println!();

    let signed_path = sideloader.sign_ipa(&ipa, &cert, &key, &profile)?;

    println!();
    println!("  {}╭─────────────────────────────────────────╮{}", theme::SUCCESS, theme::RESET);
    println!("  {}│{}     {}✅ KÝ IPA THÀNH CÔNG{}                {}│{}",
        theme::SUCCESS, theme::RESET, theme::BOLD, theme::RESET, theme::SUCCESS, theme::RESET);
    println!("  {}├─────────────────────────────────────────┤{}", theme::SUCCESS, theme::RESET);
    println!("  {}│{}  App bundle: {}", theme::SUCCESS, theme::RESET,
        signed_path.display());
    println!("  {}╰─────────────────────────────────────────╯{}", theme::SUCCESS, theme::RESET);

    Ok(())
}

// ============================================================
//  MAIN
// ============================================================

fn main() {
    // Clear screen
    print!("\x1b[2J\x1b[1;1H");

    menu::print_logo();

    let status = get_iphone_status();
    menu::print_status(&status);

    loop {
        let choice = prompt_choice();

        let result = match choice.as_str() {
            "1" => cmd_login_apple_id(),
            "2" => cmd_test_anisette(),
            "3" => cmd_test_csr(),
            "4" => cmd_sideload(),
            "5" => {
                println!();
                log::info("Tạm biệt! 👋");
                return;
            }
            _ => {
                println!();
                log::warn(&format!("Lựa chọn không hợp lệ: {}", choice));
                continue;
            }
        };

        if let Err(e) = result {
            println!();
            log::error(&format!("{:#}", e));
            let mut source = e.source();
            while let Some(s) = source {
                println!("    {} {}", theme::muted("↳"), theme::muted(&s.to_string()));
                source = s.source();
            }
        }

        pause();

        print!("\x1b[2J\x1b[1;1H");
        menu::print_logo();
        let status = get_iphone_status();
        menu::print_status(&status);
    }
}
