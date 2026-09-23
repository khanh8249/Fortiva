// src/install/installer.rs
use anyhow::{anyhow, Context, Result};
use idevice::services::installation_proxy::InstallationProxyClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::IdeviceService;
use plist::{Dictionary, Value};

/// Low-level install
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

/// High-level: nhận udid, tự kết nối usbmuxd + installation proxy
pub async fn install_app_bundle(app_path: &str, udid: &str) -> Result<()> {
    // 1. Kết nối usbmuxd daemon
    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .context("Không kết nối được usbmuxd")?;

    // 2. Lấy danh sách thiết bị
    let devices = usbmuxd
        .get_devices()
        .await
        .context("Không lấy được danh sách thiết bị")?;

    // 3. Tìm device theo udid (udid là FIELD, không phải method)
    let device = devices
        .into_iter()
        .find(|d| d.udid == udid)
        .ok_or_else(|| anyhow!("Không tìm thấy thiết bị với UDID: {}", udid))?;

    // 4. Tạo provider từ device
    let mut provider = device.to_provider(
        UsbmuxdAddr::from_env_var().unwrap_or_default(),
        "fortiva",
    );

    // 5. Kết nối InstallationProxyClient qua trait IdeviceService
    let mut instproxy = InstallationProxyClient::connect(&mut provider)
        .await
        .context("Không kết nối được InstallationProxy")?;

    // 6. Options + install
    let mut options = Dictionary::new();
    options.insert(
        "PackageType".to_string(),
        Value::String("Developer".to_string()),
    );

    install_app(&mut instproxy, app_path, options).await?;
    Ok(())
}
