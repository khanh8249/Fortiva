//! SideStore pairing file setup.
//!
//! Flow:
//! 1. Connect usbmuxd → lấy device đầu tiên
//! 2. Lockdown → đọc ProductVersion
//! 3. Pair (fresh, fallback cached record)
//! 4. Stamp UDID vào pairing file
//! 5. Bật WiFi debugging (optional)
//! 6. Serialize + validate
//! 7. Tìm SideStore bundle (auto-detect signing suffix)
//! 8. Ghi vào /Documents/ALTPairingFile.mobiledevicepairing

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::time::Duration;

use idevice::lockdown::LockdowndClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::IdeviceProvider;
use idevice::services::afc::opcode::AfcFopenMode;
use idevice::services::afc::AfcClient;
use idevice::services::house_arrest::HouseArrestClient;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::IdeviceService;

use crate::tools::validate;

const SIDESTORE_BUNDLE: &str = "com.SideStore.SideStore";
const PAIRING_FILE_NAME: &str = "ALTPairingFile.mobiledevicepairing";
const TRUST_TIMEOUT_SECS: u64 = 60;
const RPPAIRING_MIN_MAJOR: u32 = 17;
const RPPAIRING_MIN_MINOR: u32 = 4;

// ============================================================
// Public API
// ============================================================

/// Set up pairing file cho SideStore trên device đang cắm USB.
///
/// `notify` là callback để prompt user (trả `Ok(true)` để tiếp tục, `Ok(false)` để hủy).
pub async fn setup_sidestore_pairing<F>(notify: F) -> Result<()>
where
    F: Fn(&str) -> Result<bool>,
{
    println!();
    println!("======================================================");
    println!("  Setup SideStore Pairing File");
    println!("======================================================");
    println!();

    // ─── Step 1: usbmuxd ───
    println!("[1/6] Connecting to usbmuxd...");
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Không kết nối được usbmuxd. Cài đặt: pkg install usbmuxd")?;

    let devices = usbmuxd
        .get_devices()
        .await
        .context("Không lấy được danh sách device")?;

    if devices.is_empty() {
        anyhow::bail!("Chưa cắm iPhone. Cắm cáp USB và mở khóa iPhone.");
    }

    let udid = devices[0].udid.clone();
    println!("  ✓ UDID: {}", udid);

    // ─── Step 2: Lockdown ───
    println!();
    println!("[2/6] Connecting to lockdown...");

    let addr = UsbmuxdAddr::from_env_var().unwrap_or_else(|_| UsbmuxdAddr::default());
    let device = usbmuxd
        .get_devices()
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Không tìm thấy device"))?;
    let provider = device.to_provider(addr, host_label());

    let mut lockdown = LockdowndClient::connect(&provider)
        .await
        .context("Không kết nối được lockdown")?;

    let product_version = lockdown
        .get_value(Some("ProductVersion"), None)
        .await
        .context("Không đọc được ProductVersion")?
        .as_string()
        .ok_or_else(|| anyhow!("ProductVersion không phải string"))?
        .to_string();

    let (major, minor) = parse_ios_version(&product_version);
    println!("  ✓ iOS {}.{}", major, minor);

    if needs_rppairing(major, minor) {
        print_rppairing_warning(major, minor);
    }

    // ─── Step 3: Pair (fresh, fallback cached) ───
    println!();
    println!("[3/6] Pairing...");

    let mut pairing_file = match pair_fresh(&mut lockdown).await {
        Ok(pf) => {
            println!("  ✓ Pair thành công");
            pf
        }
        Err(e) => {
            println!("  [!] Pair fresh failed: {}", e);
            println!("  → Fallback: dùng cached pairing record từ usbmuxd...");

            let mut pf = usbmuxd
                .get_pair_record(&udid)
                .await
                .context("Không có cached pairing record. Chạy 'idevicepair pair' trước hoặc rút ra cắm lại.")?;

            if pf.wifi_mac_address.is_empty() {
                anyhow::bail!(
                    "Cached pairing record thiếu WiFiMACAddress. SideStore sẽ từ chối."
                );
            }
            pf.udid = Some(udid.clone());
            println!("  ✓ Dùng cached pairing record");
            pf
        }
    };

    // ─── Step 4: Stamp UDID ───
    pairing_file.udid = Some(udid.clone());
    println!("  ✓ Đã stamp UDID vào pairing file");

    // ─── Step 5: WiFi debugging (optional) ───
    println!();
    println!("[4/6] Enable WiFi debugging (optional)...");
    match lockdown
        .set_value(
            "EnableWifiDebugging",
            plist::Value::Boolean(true),
            Some("com.apple.mobile.wireless_lockdown"),
        )
        .await
    {
        Ok(()) => println!("  ✓ WiFi debugging enabled"),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("SetProhibited") {
                println!("  [i] Skipped (USB-only, OK)");
            } else {
                println!("  [!] Skipped: {}", msg);
            }
        }
    }

    // ─── Step 6: Serialize + validate ───
    println!();
    println!("[5/6] Validate pairing file...");

    let pairing_bytes = pairing_file
        .serialize()
        .context("Không serialize được pairing file")?;
    println!("  ✓ Serialize: {} bytes", pairing_bytes.len());

    let report = validate::validate_bytes(&pairing_bytes, Some(&udid))?;
    report.print();

    if !report.ok {
        anyhow::bail!("Pairing file KHÔNG hợp lệ — dừng lại trước khi ghi");
    }

    // ─── Step 7: Find SideStore ───
    println!();
    println!("[6/6] Tìm SideStore và ghi file...");

    let sidestore_id = match find_sidestore_bundle(&provider).await? {
        Some(id) => id,
        None => {
            println!();
            println!("!! ==========================================");
            println!("!!  SideStore chưa được cài trên iPhone");
            println!("!!  Cài SideStore trước rồi chạy lại tool này");
            println!("!!  https://sidestore.io");
            println!("!! ==========================================");
            let _ = notify("SideStore chưa cài. Cài rồi chạy lại tool.");
            return Ok(());
        }
    };
    println!("  ✓ Tìm thấy: {}", sidestore_id);

    // ─── Step 8: Write file ───
    write_pairing_to_bundle(&provider, &sidestore_id, &pairing_bytes).await?;

    println!();
    println!("======================================================");
    println!("  ✓ HOÀN THÀNH");
    println!();
    println!("  Mở SideStore → Settings → Health Check");
    println!("  để kiểm tra pairing file.");
    println!("======================================================");
    println!();

    let _ = notify("Done! Kiểm tra trong SideStore → Settings → Health Check.");

    Ok(())
}

/// Liệt kê tất cả file pairing record trên hệ thống.
pub fn list_pairing_records() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dirs = Vec::new();

    if let Ok(prefix) = std::env::var("PREFIX") {
        dirs.push(PathBuf::from(format!("{}/var/lib/lockdown", prefix)));
    }
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(format!("{}/.pymobiledevice3", home)));
        dirs.push(PathBuf::from(format!("{}/.usbmuxd", home)));
    }
    dirs.push(PathBuf::from(
        "/data/data/com.termux/files/usr/var/lib/lockdown",
    ));
    dirs.push(PathBuf::from("/var/lib/lockdown"));
    dirs.push(PathBuf::from("/var/db/lockdown"));

    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "plist") {
                    found.push(path);
                }
            }
        }
    }

    found
}

// ============================================================
// Internal helpers
// ============================================================

async fn pair_fresh(lockdown: &mut LockdowndClient) -> Result<PairingFile> {
    let host_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let system_buid = uuid::Uuid::new_v4().to_string().to_uppercase();

    let mut trust_prompted = false;

    for attempt in 1..=TRUST_TIMEOUT_SECS {
        match lockdown
            .pair_once(host_id.clone(), system_buid.clone(), Some(host_label()))
            .await
        {
            Ok(pf) => return Ok(pf),
            Err(idevice::IdeviceError::PairingDialogResponsePending) => {
                if !trust_prompted {
                    print_trust_prompt();
                    trust_prompted = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = attempt; // suppress unused warning
            }
            Err(e) => {
                return Err(anyhow!("Pair failed: {:?}", e));
            }
        }
    }

    Err(anyhow!(
        "Timeout sau {}s chờ Trust. Chạy lại và TAP Trust NGAY khi thấy popup.",
        TRUST_TIMEOUT_SECS
    ))
}

async fn find_sidestore_bundle(provider: &impl IdeviceProvider) -> Result<Option<String>> {
    let mut instproxy = InstallationProxyClient::connect(provider)
        .await
        .context("Không kết nối được InstallationProxy")?;

    let apps = instproxy
        .browse(None)
        .await
        .context("Không browse được apps")?;

    let all_bundles: Vec<String> = apps
        .iter()
        .filter_map(|app| app.as_dictionary())
        .filter_map(|d| {
            d.get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(String::from)
        })
        .collect();

    println!("  [i] Scan {} apps", all_bundles.len());

    // Priority 1: exact match
    if let Some(id) = all_bundles.iter().find(|id| *id == SIDESTORE_BUNDLE) {
        return Ok(Some(id.clone()));
    }

    // Priority 2: prefix match, exclude known extensions
    let prefix = format!("{}.", SIDESTORE_BUNDLE);
    let known_extensions = [
        "Widget",
        "NotificationExtension",
        "Share",
        "Intent",
        "Extension",
    ];

    for id in &all_bundles {
        if !id.starts_with(&prefix) {
            continue;
        }
        let suffix = &id[prefix.len()..];
        if !known_extensions.iter().any(|ext| suffix == *ext) {
            return Ok(Some(id.clone()));
        }
    }

    Ok(None)
}

async fn write_pairing_to_bundle(
    provider: &impl IdeviceProvider,
    bundle_id: &str,
    data: &[u8],
) -> Result<()> {
    let ha = HouseArrestClient::connect(provider)
        .await
        .context("Không kết nối được House Arrest")?;

    let mut afc: AfcClient = ha
        .vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer failed: {}", bundle_id))?;

    let remote_path = format!("/Documents/{}", PAIRING_FILE_NAME);
    println!("  → Ghi vào: {}", remote_path);

    let mut file = afc
        .open(&remote_path, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Không mở được file: {}", remote_path))?;

    file.write_entire(data)
        .await
        .with_context(|| format!("Không ghi được file: {}", remote_path))?;

    file.close().await.context("Không đóng được AFC file")?;

    println!("  ✓ Đã ghi {} bytes", data.len());
    Ok(())
}

// ============================================================
// Misc helpers
// ============================================================

fn host_label() -> &'static str {
    use std::sync::OnceLock;
    static LABEL: OnceLock<String> = OnceLock::new();
    LABEL.get_or_init(|| {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("fortiva-{}", &id[..6])
    })
}

fn parse_ios_version(v: &str) -> (u32, u32) {
    let mut parts = v.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

fn needs_rppairing(major: u32, minor: u32) -> bool {
    major > RPPAIRING_MIN_MAJOR
        || (major == RPPAIRING_MIN_MAJOR && minor >= RPPAIRING_MIN_MINOR)
}

fn print_trust_prompt() {
    println!();
    println!("!! ==========================================");
    println!("!!  TAP 'TRUST' TRÊN IPHONE NGAY BÂY GIỜ");
    println!("!!");
    println!("!!  1. Mở khóa iPhone");
    println!("!!  2. Tìm popup 'Trust This Computer?'");
    println!("!!  3. Tap 'Trust' + nhập passcode");
    println!("!!");
    println!("!!  (Timeout sau {} giây)", TRUST_TIMEOUT_SECS);
    println!("!! ==========================================");
    println!();
}

fn print_rppairing_warning(major: u32, minor: u32) {
    println!();
    println!("!! ==========================================");
    println!("!!  iOS {}.{} cần RPPairing record", major, minor);
    println!("!!");
    println!("!!  Tool này chỉ hỗ trợ Lockdown pairing.");
    println!("!!  SideStore có thể từ chối file khi cài IPA.");
    println!("!!");
    println!("!!  Khuyến nghị: Dùng PC để gen pairing file,");
    println!("!!  rồi import thủ công vào SideStore.");
    println!("!! ==========================================");
    println!();
}
