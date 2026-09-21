// src/tools/sidestore_pairing.rs
use anyhow::{anyhow, Context, Result};
use idevice::lockdown::LockdowndClient;
use idevice::services::afc::opcode::AfcFopenMode;
use idevice::services::afc::AfcClient;
use idevice::services::house_arrest::HouseArrestClient;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::UsbmuxdConnection;
use plist::{Dictionary, Value};
use std::path::PathBuf;

const PAIRING_FILE_PATH: &str = "/Documents/ALTPairingFile.mobiledevicepairing";
const SIDESTORE_BUNDLE_PREFIX: &str = "com.SideStore.SideStore";

/// Setup pairing file cho SideStore.
///
/// Ghi file `ALTPairingFile.mobiledevicepairing` vào Documents/
/// của mỗi SideStore bundle đã cài trên thiết bị.
///
/// `notify` là callback để hỏi user xác nhận (ví dụ khi pair fail).
pub async fn setup_sidestore_pairing<F>(notify: F) -> Result<()>
where
    F: Fn(&str) -> Result<bool>,
{
    println!("[sidestore] ═══ Setup pairing file ═══\n");

    // 1. Kết nối usbmuxd
    let device = connect_device().await?;
    let udid = device.udid.clone();
    println!("[sidestore] Device UDID: {}", udid);

    //  {
2. Pair với iPhone
    pair_device(&device, &notify).await?;

    // 3. Đọc pairing record
    println!("\n[sidestore] Đọc pairing record...");
    let        pairing_xml = build_pairing_xml(&udid)?;
    println!("[sidestore] Pairing file: {} bytes", pairing return_xml.len());

    // 4. Tìm SideStore bundles
    println!("\n[sidestore Err] Tìm SideStore trên thiết bị...");
    let bundles = find_sidestore_bundles(&device).await?;

    if bundles(.is_empty()anyhow!(
            "Không tìm thấy SideStore trên thiết bị.\n\
             Hãy cài SideStore trước rồi chạy lại."
        ));
    }

    println!("[sidestore] ✅ Tìm thấy {} bundle(s):", bundles.len());
    for b in &bundles {
        println!("[sidestore]   - {}", b);
    }

    // 5. Ghi pairing file vào từng bundle
    println!("\n[sidestore] Ghi pairing file vào container...");
    let (success, failed) = write_to_bundles(&device, &bundles, &pairing_xml, &notify).await;

    // 6. Tổng kết
    println!("\n[sidestore] ═══ Kết quả ═══");
    println!("[sidestore] Thành công: {}/{}", success, bundles.len());

    if !failed.is_empty() {
        println!("[sidestore] Thất bại:");
        for b in &failed {
            println!("[sidestore]   - {}", b);
        }
    }

    if success == 0 {
        return Err(anyhow!("Không ghi được vào SideStore bundle nào"));
    }

    println!("\n[sidestore] ✅ Hoàn tất!");
    println!("[sidestore] Mở SideStore → Settings để kiểm tra.");
    Ok(())
}

/// Liệt kê tất cả pairing records có trên hệ thống.
pub fn list_pairing_records() -> Vec<PathBuf> {
    let mut found = Vec::new();

    for dir in pairing_dirs() {
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
//  INTERNAL HELPERS
// ============================================================

/// Kết nối usbmuxd, trả về device đầu tiên.
async fn connect_device() -> Result<idevice::usbmuxd::UsbmuxdDevice> {
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Kết nối usbmuxd thất bại. usbmuxd đã chạy chưa?")?;

    let devices = usbmuxd
        .get_devices()
        .await
        .context("Lấy danh sách device thất bại")?;

    if devices.is_empty() {
        return Err(anyhow!(
            "Không tìm thấy iPhone. Kiểm tra:\n\
             - Cáp USB đã cắm chưa\n\
             - iPhone đã unlock chưa\n\
             - usbmuxd đang chạy chưa (pgrep usbmuxd)"
        ));
    }

    Ok(devices.into_iter().next().unwrap())
}

/// Pair với iPhone, retry nếu user chưa trust.
async fn pair_device<F>(
    device: &idevice::usbmuxd::UsbmuxdDevice,
    notify: &F,
) -> Result<()>
where
    F: Fn(&str) -> Result<bool>,
{
    println!("\n[sidestore] Pairing với iPhone...");

    let mut lockdown = LockdowndClient::connect(device)
        .await
        .context("Kết nối Lockdownd thất bại")?;

    loop {
        match lockdown.pair().await {
            Ok(()) => {
                println!("[sidestore] ✅ Pairing OK");
                return Ok(());
            }
            Err(e) => {
                let msg = format!(
                    "Pairing fail: {}\n\n\
                     Kiểm tra trên iPhone:\n\
                     - Đã mở khóa màn hình chưa?\n\
                     - Đã bấm 'Trust This Computer' chưa?\n\n\
                     Thử lại?",
                    e
                );
                if !notify(&msg)? {
                    return Err(anyhow!("User hủy pairing"));
                }
            }
        }
    }
}

/// Đọc pairing record và build XML để ghi vào SideStore.
fn build_pairing_xml(udid: &str) -> Result<Vec<u8>> {
    let path = find_pairing_record(udid)?;
    println!("[sidestore] Tìm thấy: {}", path.display());

    let data = std::fs::read(&path)
        .with_context(|| format!("Đọc file thất bại: {}", path.display()))?;

    let mut record: Dictionary =
        plist::from_bytes(&data).context("Parse pairing record thất bại")?;

    // SideStore cần UDID trong record
    record.insert("UDID".into(), Value::String(udid.to_string()));

    let xml = plist::to_formatted_writer(&mut Vec::new(), &Value::Dictionary(record))
        .context("Serialize pairing record thất bại")?;

    Ok(xml)
}

/// Tìm file pairing record của UDID.
fn find_pairing_record(udid: &str) -> Result<PathBuf> {
    let filename = format!("{}.plist", udid);

    for dir in pairing_dirs() {
        let path = dir.join(&filename);
        if path.exists() {
            return Ok(path);
        }
    }

    // Không tìm thấy
    let tried = pairing_dirs()
        .iter()
        .map(|d| format!("  - {}", d.join(&filename).display()))
        .collect::<Vec<_>>()
        .join("\n");

    let prefix = std::env::var("PREFIX")
        .unwrap_or_else(|_| "/data/data/com.termux/files/usr".to_string());

    Err(anyhow!(
        "Không tìm thấy pairing record cho {}.\n\n\
         Đã thử:\n{}\n\n\
         Cách fix:\n\
         1. Chạy: idevicepair -u {} pair\n\
         2. Kiểm tra usbmuxd: pgrep usbmuxd\n\
         3. Kiểm tra thư mục: ls -la {}/var/lib/lockdown/",
        udid,
        tried,
        udid,
        prefix
    ))
}

/// Danh sách thư mục có thể chứa pairing record.
/// Ưu tiên Termux trước.
fn pairing_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // 1. Termux ($PREFIX)
    if let Ok(prefix) = std::env::var("PREFIX") {
        dirs.push(PathBuf::from(format!("{}/var/lib/lockdown", prefix)));
    }

    // 2. Termux hardcode (fallback)
    dirs.push(PathBuf::from(
        "/data/data/com.termux/files/usr/var/lib/lockdown",
    ));

    // 3. Termux HOME
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(format!("{}/.pymobiledevice3", home)));
        dirs.push(PathBuf::from(format!("{}/.usbmuxd", home)));
        dirs.push(PathBuf::from(format!("{}/usbmuxd/var/lib/lockdown", home)));
    }

    // 4. Linux chuẩn
    dirs.push(PathBuf::from("/var/lib/lockdown"));

    // 5. macOS
    dirs.push(PathBuf::from("/var/db/lockdown"));

    dirs
}

/// Tìm tất cả SideStore bundles đã cài.
async fn find_sidestore_bundles(
    device: &idevice::usbmuxd::UsbmuxdDevice,
) -> Result<Vec<String>> {
    let lockdown = LockdowndClient::connect(device)
        .await
        .context("Kết nối Lockdownd thất bại")?;

    let instproxy_service = lockdown
        .start_service("com.apple.mobile.installation_proxy")
        .await
        .context("Start InstallationProxy service thất bại")?;

    let mut instproxy = InstallationProxyClient::new(instproxy_service)
        .await
        .context("Tạo InstallationProxy client thất bại")?;

    let mut options = Dictionary::new();
    options.insert("ApplicationType".into(), Value::String("User".into()));
    options.insert(
        "ReturnAttributes".into(),
        Value::Array(vec![Value::String("CFBundleIdentifier".into())]),
    );

    let apps = instproxy
        .browse(Some(Value::Dictionary(options)))
        .await
        .context("Browse apps thất bại")?;

    let bundles: Vec<String> = apps
        .iter()
        .filter_map(|app| app.as_dictionary())
        .filter_map(|d| {
            d.get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
        })
        .filter(|id| id.starts_with(SIDESTORE_BUNDLE_PREFIX))
        .collect();

    Ok(bundles)
}

/// Ghi pairing file vào từng bundle.
/// Trả về (số thành công, danh sách bundle thất bại).
async fn write_to_bundles<F>(
    device: &idevice::usbmuxd::UsbmuxdDevice,
    bundles: &[String],
    pairing_xml: &[u8],
    notify: &F,
) -> (usize, Vec<String>)
where
    F: Fn(&str) -> Result<bool>,
{
    let mut success = 0;
    let mut failed = Vec::new();

    for (idx, bundle_id) in bundles.iter().enumerate() {
        println!(
            "\n[sidestore] ({}/{}) {}",
            idx + 1,
            bundles.len(),
            bundle_id
        );

        match write_to_bundle(device, bundle_id, pairing_xml).await {
            Ok(()) => {
                println!("[sidestore] ✅ OK");
                success += 1;
            }
            Err(e) => {
                println!("[sidestore] ❌ {}", e);
                failed.push(bundle_id.clone());

                // Nếu còn bundle khác → hỏi user
                if idx + 1 < bundles.len() {
                    let msg = format!(
                        "Ghi thất bại vào {}.\nTiếp tục với bundle khác?",
                        bundle_id
                    );
                    match notify(&msg) {
                        Ok(true) => continue,
                        _ => break,
                    }
                }
            }
        }
    }

    (success, failed)
}

/// Ghi pairing file vào 1 bundle qua House Arrest + AFC.
async fn write_to_bundle(
    device: &idevice::usbmuxd::UsbmuxdDevice,
    bundle_id: &str,
    pairing_xml: &[u8],
) -> Result<()> {
    // 1. Mở House Arrest
    let lockdown = LockdowndClient::connect(device)
        .await
        .context("Kết nối Lockdownd thất bại")?;

    let ha_service = lockdown
        .start_service("com.apple.mobile.house_arrest")
        .await
        .context("Start House Arrest service thất bại")?;

    let mut ha = HouseArrestClient::new(ha_service)
        .await
        .context("Tạo House Arrest client thất bại")?;

    // 2. Vend container (toàn bộ Documents + Library)
    ha.vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer thất bại cho {}", bundle_id))?;

    // 3. Chuyển sang AFC
    let mut afc = AfcClient::new(ha.into_inner())
        .await
        .context("Tạo AFC client thất bại")?;

    // 4. Ghi file
    let mut file = afc
        .open(PAIRING_FILE_PATH, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Mở file thất bại: {}", PAIRING_FILE_PATH))?;

    file.write_entire(pairing_xml)
        .await
        .context("Ghi file thất bại")?;

    file.close().await.context("Close file thất bại")?;

    println!(
        "[sidestore]   Ghi {} bytes vào {}",
        pairing_xml.len(),
        PAIRING_FILE_PATH
    );

    Ok(())
}