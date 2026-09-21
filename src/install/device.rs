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
pub fn detect_device() -> Result<DeviceInfo> {
    println!("[device] Đang tìm thiết bị iOS qua USB...");

    let usbmuxd_addr = UsbmuxdAddr::default();
    let mut conn = UsbmuxdConnection::default()
        .context("Kết nối usbmuxd thất bại. usbmuxd đã chạy chưa?")?;

    let devices = conn
        .get_devices()
        .context("Lấy danh sách thiết bị thất bại")?;

    if devices.is_empty() {
        return Err(anyhow!(
            "Không tìm thấy thiết bị iOS. Kiểm tra:\n\
             - Cáp USB đã cắm chưa\n\
             - iPhone đã Trust máy này chưa\n\
             - usbmuxd đã chạy chưa"
        ));
    }

    let dev = &devices[0];
    let udid = dev.udid.clone();

    println!("[device] Tìm thấy thiết bị: {}", udid);

    Ok(DeviceInfo {
        udid,
        name: format!("iPhone-{}", &udid[..8.min(udid.len())]),
    })
}

/// Kiểm tra thiết bị đã trust chưa.
pub fn ensure_trusted(provider: &impl IdeviceProvider) -> Result<()> {
    // idevice crate sẽ tự raise lỗi nếu chưa trust khi connect
    // Hàm này chỉ để wrap error message
    Ok(())
}