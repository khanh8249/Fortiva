// src/install/installer.rs
use anyhow::{anyhow, Context, Result};
use idevice::services::afc::AfcClient;
use idevice::services::afc::opcode::AfcFopenMode;
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::IdeviceService;
use plist::{Dictionary, Value};
use std::path::Path;

// ============================================================
//  LOW-LEVEL: install with remote path
// ============================================================

pub async fn install_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: Dictionary,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |_| async {},
            (),
        )
        .await
        .context("Install thất bại")?;
    Ok(())
}

pub async fn upgrade_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: Dictionary,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |_| async {},
            (),
        )
        .await
        .context("Upgrade thất bại")?;
    Ok(())
}

// ============================================================
//  HIGH-LEVEL: upload IPA + install
// ============================================================

pub async fn install_app_bundle(app_path: &str, udid: &str) -> Result<()> {
    println!();
    println!("[install] === INSTALL APP BUNDLE ===");
    println!("[install] Local: {}", app_path);
    println!("[install] UDID:  {}", udid);
    println!();

    // 1. Check file local
    let local_path = Path::new(app_path);
    if !local_path.exists() {
        return Err(anyhow!("IPA không tồn tại: {}", app_path));
    }

    // 2. Connect usbmuxd
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Không kết nối được usbmuxd")?;

    // 3. Tìm device
    let devices = usbmuxd
        .get_devices()
        .await
        .context("Không lấy được danh sách thiết bị")?;

    let device = devices
        .into_iter()
        .find(|d| d.udid == udid)
        .ok_or_else(|| anyhow!("Không tìm thấy thiết bị: {}", udid))?;

    println!("[install] Tìm thấy device");

    // 4. Provider
    let mut provider = device.to_provider(
        UsbmuxdAddr::from_env_var().unwrap_or_default(),
        "fortiva",
    );

    // 5. Connect AFC
    println!("[install] Connect AFC...");
    let mut afc = AfcClient::new_afc2(&provider)
        .await
        .context("Không connect được AFC")?;
    println!("[install] AFC connected");

    // 6. Đảm bảo /PublicStaging tồn tại
    let _ = afc.mk_dir("/PublicStaging").await;

    // 7. Upload IPA
    let file_name = local_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Không lấy được filename"))?
        .to_string();

    let remote_path = format!("/PublicStaging/{}", file_name);

    println!("[install] Đọc IPA...");
    let data = tokio::fs::read(app_path)
        .await
        .with_context(|| format!("Đọc file fail: {}", app_path))?;

    let size_mb = data.len() as f64 / 1_048_576.0;
    println!("[install] Size: {:.2} MB", size_mb);
    println!("[install] Upload → {}", remote_path);

    let mut file = afc
        .open(&remote_path, AfcFopenMode::Wr)
        .await
        .with_context(|| format!("Open remote fail: {}", remote_path))?;

    file.write_entire(&data)
        .await
        .context("Write remote fail")?;

    file.close().await.context("Close remote fail")?;

    println!("[install] ✅ Uploaded");

    // 8. Connect InstallationProxy
    println!("[install] Connect InstallationProxy...");
    let mut instproxy = InstallationProxyClient::connect(&mut provider)
        .await
        .context("Không kết nối được InstallationProxy")?;

    // 9. Options
    let mut options = Dictionary::new();
    options.insert(
        "PackageType".to_string(),
        Value::String("Developer".to_string()),
    );

    // 10. Install
    println!("[install] Trigger install...");
    install_app(&mut instproxy, &remote_path, options).await?;

    println!();
    println!("[install] ✅ CÀI THÀNH CÔNG!");
    println!();

    Ok(())
}
