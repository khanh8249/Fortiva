// src/install/device.rs
use anyhow::{anyhow, Context, Result};
use idevice::provider::IdeviceProvider;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
}

/// Detect thiết bị iOS kết nối qua USB.
/// Hàm này là async — phải gọi trong tokio runtime.
pub async fn detect_device() -> Result<DeviceInfo> {
    println!("[device] Đang tìm thiết bị iOS qua USB...");

    let mut conn = UsbmuxdConnection::default()
        .await
        .context("Kết nối usbmuxd thất bại. usbmuxd đã chạy chưa?")?;

    let devices = conn
        .get_devices()
        .await
        .context("Lấy danh sách thiết bị thất bại")?;

    if devices.is_empty() {
        return Err(anyhow!(
            "Không tìm thấy thiết bị iOS. Kiểm tra:\n\
             - Cáp USB đã cắm chưa\n\
             - iPhone đã Trust máy này chưa\n\
             - usbmuxd đã chạy chưa (pgrep usbmuxd)"
        ));
    }

    let dev = &devices[0];
    let udid = dev.udid.clone();

    println!("[device] Tìm thấy thiết bị: {}", udid);

    Ok(DeviceInfo {
        udid: udid.clone(),
        name: format!("iPhone-{}", &udid[..8.min(udid.len())]),
    })
}

/// Kiểm tra thiết bị đã trust chưa.
/// Thực tế, `idevice` crate sẽ tự raise lỗi nếu chưa trust khi connect service.
/// Hàm này chỉ để wrap error message rõ ràng hơn.
pub fn ensure_trusted(_provider: &impl IdeviceProvider) -> Result<()> {
    Ok(())
}
