// src/install/afc_rsd.rs
use anyhow::{anyhow, Context, Result};
use idevice::afc::opcode::AfcFopenMode;
use idevice::afc::AfcClient;
use idevice::provider::RsdProvider;
use idevice::rsd::RsdHandshake;
use std::path::Path;

/// Upload thư mục .app lên iPhone qua AFC (RSD mode, iOS 17+).
pub async fn upload_app_bundle_rsd(
    provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<String> {
    println!("[afc-rsd] Kết nối AFC qua RSD...");

    let mut afc = AfcClient::connect_rsd(provider, handshake)
        .await
        .context("Kết nối AFC qua RSD thất bại")?;

    let app_name = app_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Không đọc được tên app"))?;

    let remote_dir = format!("PublicStaging/{}", app_name);

    println!("[afc-rsd] Upload vào: {}", remote_dir);

    let total_size = get_dir_size(app_path).unwrap_or(1) as f64;
    let mut uploaded = 0u64;

    upload_dir_recursive_rsd(
        &mut afc,
        app_path,
        &remote_dir,
        &mut uploaded,
        total_size,
        &progress_callback,
    )
    .await?;

    println!("[afc-rsd] ✅ Upload xong: {}", remote_dir);
    Ok(remote_dir)
}

async fn upload_dir_recursive_rsd(
    afc: &mut AfcClient,
    local_path: &Path,
    remote_path: &str,
    uploaded: &mut u64,
    total: f64,
    cb: &(impl Fn(u64) + Send + Sync),
) -> Result<()> {
    afc.mk_dir(remote_path)
        .await
        .with_context(|| format!("Tạo thư mục thất bại: {}", remote_path))?;

    let mut entries = tokio::fs::read_dir(local_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let name = entry.file_name().to_str().unwrap_or("").to_string();
        let remote_sub = format!("{}/{}", remote_path, name);

        let meta = tokio::fs::symlink_metadata(&path).await?;

        if meta.is_dir() {
            Box::pin(upload_dir_recursive_rsd(
                afc,
                &path,
                &remote_sub,
                uploaded,
                total,
                cb,
            ))
            .await?;
        } else if meta.file_type().is_symlink() {
            let target = tokio::fs::read_link(&path).await?;
            let target_str = target.to_string_lossy().to_string();

            let mut handle = afc.open(remote_sub.clone(), AfcFopenMode::WrOnly).await?;
            handle.write_entire(target_str.as_bytes()).await?;
            handle.close().await?;
            *uploaded += target_str.len() as u64;
            cb((*uploaded as f64 / total * 100.0) as u64);
        } else {
            let mut handle = afc.open(remote_sub.clone(), AfcFopenMode::WrOnly).await?;
            let bytes = tokio::fs::read(&path).await?;

            for chunk in bytes.chunks(8 * 1024) {
                handle.write_entire(chunk).await?;
                *uploaded += chunk.len() as u64;
                cb((*uploaded as f64 / total * 100.0) as u64);
            }

            handle.close().await?;
        }
    }

    Ok(())
}

fn get_dir_size(path: &Path) -> Result<u64> {
    let mut size = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            size += get_dir_size(&entry.path())?;
        } else {
            size += meta.len();
        }
    }
    Ok(size)
}