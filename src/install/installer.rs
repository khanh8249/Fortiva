// src/install/installer.rs
use anyhow::{Context, Result};
use idevice::installation_proxy::InstallationProxyClient;
use idevice::provider::{IdeviceProvider, RsdProvider};
use idevice::rsd::RsdHandshake;
use plist::Value;
use std::path::Path;

use super::afc::{upload_app_bundle};
use super::afc_rsd::upload_app_bundle_rsd;

/// Cài app (usbmuxd mode).
pub async fn install_app(
    provider: &impl IdeviceProvider,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<()> {
    println!("[install] Bắt đầu cài: {}", app_path.display());

    // Bước 1: Upload qua AFC (chiếm 0-70% progress)
    let remote_dir = upload_app_bundle(provider, app_path, |pct| {
        progress_callback((pct as f64 * 0.7) as u64);
    })
    .await?;

    // Bước 2: Trigger install (chiếm 70-100% progress)
    println!("[install] Trigger install qua InstallationProxy...");

    let mut instproxy = InstallationProxyClient::connect(provider)
        .await
        .context("Kết nối InstallationProxy thất bại")?;

    // Options
    let mut options = plist::Dictionary::new();
    options.insert(
        "PackageType".to_string(),
        Value::String("Developer".to_string()),
    );

    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |(percentage, _)| {
                let pct = (70.0 + 0.3 * percentage as f64) as u64;
                progress_callback(pct);
            },
            (),
        )
        .await
        .context("Install thất bại")?;

    println!("[install] ✅ Cài thành công");
    Ok(())
}

/// Cài app (RSD mode, iOS 17+).
pub async fn install_app_rsd(
    provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<()> {
    println!("[install-rsd] Bắt đầu cài: {}", app_path.display());

    // Upload qua AFC RSD
    let remote_dir = upload_app_bundle_rsd(provider, handshake, app_path, |pct| {
        progress_callback((pct as f64 * 0.7) as u64);
    })
    .await?;

    // Trigger install
    println!("[install-rsd] Trigger install...");

    let mut instproxy = InstallationProxyClient::connect_rsd(provider, handshake)
        .await
        .context("Kết nối InstallationProxy qua RSD thất bại")?;

    let mut options = plist::Dictionary::new();
    options.insert(
        "PackageType".to_string(),
        Value::String("Developer".to_string()),
    );

    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |(percentage, _)| {
                let pct = (70.0 + 0.3 * percentage as f64) as u64;
                progress_callback(pct);
            },
            (),
        )
        .await
        .context("Install qua RSD thất bại")?;

    println!("[install-rsd] ✅ Cài thành công");
    Ok(())
}