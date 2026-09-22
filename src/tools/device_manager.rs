// src/tools/device_manager.rs
//
// Quản lý thiết bị: list, register, remove devices trên Apple Developer.

use anyhow::{anyhow, Context, Result};

use crate::auth::anisette::AnisetteClient;
use crate::dev::DeveloperClient;

/// In danh sách thiết bị đã đăng ký.
pub fn list_devices(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
) -> Result<()> {
    let devices = dev
        .list_devices_full(auth)
        .context("List devices thất bại")?;

    if devices.is_empty() {
        println!("  ⚠️ Chưa có thiết bị nào đăng ký.");
        return Ok(());
    }

    println!("  Tìm thấy {} thiết bị:\n", devices.len());
    println!("  {:<4} {:<40} {}", "STT", "UDID", "Tên");
    println!("  {}", "─".repeat(80));

    for (i, d) in devices.iter().enumerate() {
        println!(
            "  {:<4} {:<40} {}",
            i + 1,
            d.udid,
            d.name
        );
    }

    Ok(())
}

/// Đăng ký thiết bị mới bằng UDID.
pub fn register_device(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
    name: &str,
    udid: &str,
) -> Result<()> {
    let device = dev
        .ensure_device_registered(auth, name, udid)
        .context("Đăng ký thiết bị thất bại")?;

    println!(
        "  ✅ Đã đăng ký: {} ({})",
        device.name,
        device.udid
    );

    Ok(())
}

/// Đăng ký thiết bị đang kết nối qua USB.
pub fn register_usb_device(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
) -> Result<()> {
    let output = std::process::Command::new("idevice_id")
        .arg("-l")
        .output()
        .context("Chạy idevice_id thất bại")?;

    if !output.status.success() {
        return Err(anyhow!("idevice_id thất bại"));
    }

    let udid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();

    if udid.is_empty() {
        return Err(anyhow!("Không tìm thấy thiết bị USB"));
    }

    println!("  UDID: {}", udid);

    let prefix_len = std::cmp::min(8, udid.len());
    let name = format!("iPhone-{}", &udid[..prefix_len]);

    register_device(dev, auth, &name, &udid)
}
