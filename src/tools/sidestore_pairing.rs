//! # SideStore Pairing File Setup
//!
//! Generates a pairing file for SideStore and writes it into the app's container.
//!
//! ## Flow
//!
//! 1. Connect to usbmuxd -> grab the first device
//! 2. Connect to lockdown -> read ProductVersion
//! 3. Create a Lockdown pairing (fresh pair, fall back to cache on failure)
//! 4. Stamp UDID into the pairing file (required by SideStore)
//! 5. Enable WiFi debugging (optional, helps SideStore connect over WiFi)
//! 6. Serialize + validate the plist
//! 7. Write to /Documents/ALTPairingFile.mobiledevicepairing
//!
//! ## Current limitations (Plan A)
//!
//! - iOS 16.x and 17.0-17.3: fully supported
//! - iOS 17.4+: requires an RPPairing record -> not yet supported
//! - iOS 18+: same as iOS 17.4+
//!
//! Users on iOS 17.4+ should use idevice_pair on a PC to generate the pairing
//! file, then import it manually into SideStore.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use idevice::lockdown::LockdownClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::IdeviceProvider;
use idevice::services::afc::{opcode::AfcFopenMode, AfcClient};
use idevice::services::house_arrest::HouseArrestClient;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::IdeviceService;

const SIDESTORE_BUNDLE: &str = "com.SideStore.SideStore";
const PAIRING_FILE_NAME: &str = "ALTPairingFile.mobiledevicepairing";
const RPPAIRING_MIN_MAJOR: u32 = 17;
const RPPAIRING_MIN_MINOR: u32 = 4;
const TRUST_TIMEOUT_SECS: u64 = 60;

// ============================================================
// Public API
// ============================================================

pub async fn setup_sidestore_pairing<F>(notify: F) -> Result<()>
where
    F: Fn(&str) -> Result<bool>,
{
    print_header("Setup SideStore Pairing File");

    // Step 1: Connect to usbmuxd
    let (mut usbmuxd, udid) = connect_usbmuxd().await?;

    // Step 2: Lockdown + version check
    let addr = UsbmuxdAddr::from_env_var().unwrap_or_else(|_| UsbmuxdAddr::default());
    let device = usbmuxd
        .get_devices()
        .await
        .context("Failed to fetch device list")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No iPhone connected"))?;
    let provider = device.to_provider(addr, host_label());

    let mut lc = LockdownClient::connect(&provider)
        .await
        .context("Failed to connect to lockdown")?;

    let product_version = lc
        .get_value(Some("ProductVersion"), None)
        .await
        .context("Failed to read ProductVersion")?
        .as_string()
        .ok_or_else(|| anyhow!("ProductVersion is not a string"))?
        .to_string();

    let (major, minor) = parse_ios_version(&product_version);
    log_info(&format!("iPhone iOS {}.{}", major, minor));

    if needs_rppairing(major, minor) {
        print_rppairing_warning(major, minor);
    }

    // Step 3: Pair (fresh, fallback to cache)
    let mut pairing_file = pair_with_fallback(&mut lc, &mut usbmuxd, &udid).await?;

    // Step 4: Stamp UDID
    pairing_file.udid = Some(udid.clone());
    log_success("Stamped UDID into pairing file");

    // Step 5: Enable WiFi debugging
    try_enable_wifi_debugging(&mut lc).await;

    // Step 6: Serialize + validate
    let pairing_bytes = pairing_file
        .serialize()
        .context("Failed to serialize pairing file")?;
    log_info(&format!("Pairing file: {} bytes", pairing_bytes.len()));
    validate_pairing_plist(&pairing_bytes)?;
    log_success("Pairing file is valid");

    // Step 7: Find SideStore
    ensure_sidestore_installed(&provider).await?;

    // Step 8: Write file
    write_pairing_to_bundle(&provider, SIDESTORE_BUNDLE, &pairing_bytes).await?;

    print_footer_success();
    let _ = notify("Done! Open SideStore -> Settings -> Health Check to verify.");

    Ok(())
}

// ============================================================
// Step 1: usbmuxd
// ============================================================

async fn connect_usbmuxd() -> Result<(UsbmuxdConnection, String)> {
    step("1/5", "Connecting to usbmuxd");

    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Failed to connect to usbmuxd")?;

    let devices = usbmuxd
        .get_devices()
        .await
        .context("Failed to fetch devices")?;

    if devices.is_empty() {
        return Err(anyhow!(
            "No iPhone connected. Plug in the USB cable and unlock the iPhone."
        ));
    }

    let udid = devices[0].udid.clone();
    log_info(&format!("UDID: {}", udid));

    Ok((usbmuxd, udid))
}

// ============================================================
// Step 3: Pair with fallback
// ============================================================

async fn pair_with_fallback(
    lc: &mut LockdownClient,
    usbmuxd: &mut UsbmuxdConnection,
    udid: &str,
) -> Result<PairingFile> {
    step("3/5", "Creating Lockdown pairing");

    match pair_fresh(lc).await {
        Ok(pf) => {
            log_success("Pair succeeded");
            Ok(pf)
        }
        Err(e) => {
            log_warn(&format!("Fresh pair failed: {}", e));
            log_info("Fallback: using cached pairing record from usbmuxd...");

            let mut pf = usbmuxd
                .get_pair_record(udid)
                .await
                .context("Failed to fetch cached pairing record. Run 'idevicepair pair' first, or reconnect the iPhone.")?;
            pf.udid = Some(udid.to_string());

            if pf.wifi_mac_address.is_empty() {
                return Err(anyhow!(
                    "Cached pairing record is missing WiFiMACAddress. Cannot be used for SideStore. Pair again with 'idevicepair pair' or re-run this tool."
                ));
            }

            log_success("Using cached pairing record");
            Ok(pf)
        }
    }
}

async fn pair_fresh(lc: &mut LockdownClient) -> Result<PairingFile> {
    let host_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let system_buid = uuid::Uuid::new_v4().to_string().to_uppercase();

    for attempt in 1..=TRUST_TIMEOUT_SECS {
        match lc
            .pair_once(host_id.clone(), system_buid.clone(), Some(host_label()))
            .await
        {
            Ok(pf) => return Ok(pf),
            Err(idevice::IdeviceError::PairingDialogResponsePending) => {
                if attempt == 1 {
                    print_trust_prompt();
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                return Err(anyhow!("Pair failed: {:?}", e));
            }
        }
    }

    Err(anyhow!(
        "Timeout after {}s waiting for Trust on the iPhone. Re-run and tap Trust IMMEDIATELY when you see the prompt.",
        TRUST_TIMEOUT_SECS
    ))
}

// ============================================================
// Step 5: WiFi debugging
// ============================================================

async fn try_enable_wifi_debugging(lc: &mut LockdownClient) {
    step("4/5", "Enabling WiFi debugging (optional)");

    if let Err(e) = lc
        .set_value(
            "EnableWifiDebugging",
            plist::Value::Boolean(true),
            Some("com.apple.mobile.wireless_lockdown"),
        )
        .await
    {
        log_warn(&format!("Skipped: {}", e));
    } else {
        log_success("WiFi debugging enabled");
    }
}

// ============================================================
// Step 7: Verify SideStore installed
// ============================================================

async fn ensure_sidestore_installed(provider: &impl IdeviceProvider) -> Result<()> {
    step("5/5", "Looking for SideStore on the iPhone");

    let mut instproxy = InstallationProxyClient::connect(provider)
        .await
        .context("Failed to connect to InstallationProxy")?;

    let apps = instproxy
        .browse(None)
        .await
        .context("Failed to browse apps")?;

    let found = apps
        .iter()
        .filter_map(|app| app.as_dictionary())
        .filter_map(|d| {
            d.get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(String::from)
        })
        .any(|id| id == SIDESTORE_BUNDLE);

    if !found {
        return Err(anyhow!(
            "SideStore not found on the iPhone. Install SideStore first, then re-run this tool. Guide: https://sidestore.io"
        ));
    }

    log_success("SideStore found");
    Ok(())
}

// ============================================================
// Step 8: Write file
// ============================================================

async fn write_pairing_to_bundle(
    provider: &impl IdeviceProvider,
    bundle_id: &str,
    data: &[u8],
) -> Result<()> {
    let ha = HouseArrestClient::connect(provider)
        .await
        .context("Failed to connect to House Arrest")?;

    let mut afc: AfcClient = ha
        .vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer failed: {}", bundle_id))?;

    let remote_path = format!("/Documents/{}", PAIRING_FILE_NAME);

    log_info(&format!("Writing to: {}", remote_path));

    let mut file = afc
        .open(&remote_path, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Failed to open file: {}", remote_path))?;

    file.write_entire(data)
        .await
        .with_context(|| format!("Failed to write file: {}", remote_path))?;

    file.close().await.context("Failed to close AFC file")?;

    log_success(&format!("Wrote {} bytes", data.len()));
    Ok(())
}

// ============================================================
// Validate
// ============================================================

fn validate_pairing_plist(data: &[u8]) -> Result<()> {
    let val: plist::Value = plist::from_bytes(data).context("Pairing data is not a plist")?;

    let dict = val
        .as_dictionary()
        .ok_or_else(|| anyhow!("Pairing data is not a dictionary"))?;

    const REQUIRED: &[&str] = &[
        "DeviceCertificate",
        "HostCertificate",
        "HostPrivateKey",
        "RootCertificate",
        "RootPrivateKey",
        "SystemBUID",
        "HostID",
        "WiFiMACAddress",
        "UDID",
    ];

    for key in REQUIRED {
        if !dict.contains_key(*key) {
            return Err(anyhow!("Pairing file is missing key '{}'", key));
        }
    }

    if dict
        .get("UDID")
        .and_then(|v| v.as_string())
        .is_none_or(str::is_empty)
    {
        return Err(anyhow!("UDID is empty or invalid"));
    }

    if dict
        .get("WiFiMACAddress")
        .and_then(|v| v.as_string())
        .is_none_or(str::is_empty)
    {
        return Err(anyhow!("WiFiMACAddress is empty - SideStore will reject it"));
    }

    Ok(())
}

// ============================================================
// Helpers
// ============================================================

fn host_label() -> &'static str {
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
        if let Ok(entries) = fs::read_dir(&dir) {
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
// Pretty print helpers
// ============================================================

fn print_header(title: &str) {
    println!();
    println!("======================================================");
    println!("  {}", title);
    println!("======================================================");
    println!();
}

fn print_footer_success() {
    println!();
    println!("======================================================");
    println!("  [OK] DONE");
    println!();
    println!("  Open SideStore -> Settings -> Health Check");
    println!("  to verify the pairing file.");
    println!("======================================================");
    println!();
}

fn print_trust_prompt() {
    println!();
    println!("======================================================");
    println!();
    println!("   >>>  TAP 'TRUST' ON YOUR IPHONE NOW");
    println!();
    println!("   1. Unlock the iPhone screen");
    println!("   2. Look for the 'Trust This Computer?' popup");
    println!("   3. Tap 'Trust' + enter passcode if prompted");
    println!();
    println!("   (Times out after 60 seconds)");
    println!();
    println!("======================================================");
    println!();
}

fn print_rppairing_warning(major: u32, minor: u32) {
    println!();
    println!("!! =====================================================");
    println!("!! iOS {}.{} requires an RPPairing record for SideStore.", major, minor);
    println!("!!");
    println!("!! Plan A currently only supports Lockdown pairing.");
    println!("!! The tool will try to write Lockdown pairing anyway,");
    println!("!! but you may hit UnexpectedEof when installing IPAs.");
    println!("!!");
    println!("!! Recommendation:");
    println!("!! -> Use idevice_pair on a PC to generate the pairing file");
    println!("!! -> Or wait for the Plan B build (RPPairing support)");
    println!("!! =====================================================");
    println!();
}

fn step(n: &str, msg: &str) {
    println!();
    println!("> [{}] {}", n, msg);
}

fn log_info(msg: &str) {
    println!("   [i] {}", msg);
}

fn log_success(msg: &str) {
    println!("   [OK] {}", msg);
}

fn log_warn(msg: &str) {
    println!("   [!] {}", msg);
}
