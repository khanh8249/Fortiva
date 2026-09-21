// src/install/afc.rs
use anyhow::{anyhow, Context, Result};
use idevice::afc::opcode::AfcFopenMode;
use idevice::afc::AfcClient;
use idevice::provider::IdeviceProvider;
use std::path::Path;

/// Upload thư mục .app lên iPhone qua AFC (usbmuxd mode).
pub async fn upload_app_bundle(
    provider: &impl IdeviceProvider,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<String> {
    println!("[afc] Kết nối AFC...");

    let mut afc = AfcClient::connect(provider)
        .await
        .context("Kết nối AFC thất bại")?;

    let app_name = app_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Không đọc được tên app"))?;

    let remote_dir = format!("PublicStaging/{}", app_name);

    println!("[afc] Upload vào: {}", remote_dir);

    // Tính tổng size
    let total_size = get_dir_size(app_path).unwrap_or(1) as f64;
    let mut uploaded = 0u64;

    // Upload đệ quy
    upload_dir_recursive(
        &mut afc,
        app_path,
        &remote_dir,
        &mut uploaded,
        total_size,
        &progress_callback,
    )
    .await?;

    println!("[afc] ✅ Upload xong: {}", remote_dir);
    Ok(remote_dir)
}

async fn upload_dir_recursive(
    afc: &mut AfcClient,
    local_path: &Path,
    remote_path: &str,
    uploaded: &mut u64,
    total: f64,
    cb: &(impl Fn(u64) + Send + Sync),
) -> Result<()> {
    // Tạo thư mục trên iPhone
    afc.mk_dir(remote_path)
        .await
        .with_context(|| format!("Tạo thư mục thất bại: {}", remote_path))?;

    let mut entries = tokio::fs::read_dir(local_path)
        .await
        .with_context(|| format!("Đọc thư mục thất bại: {}", local_path.display()))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow!("Tên file không hợp lệ"))?
            .to_string();

        let remote_sub = format!("{}/{}", remote_path, name);

        let meta = tokio::fs::symlink_metadata(&path).await?;

        if meta.is_dir() {
            // Đệ quy
            Box::pin(upload_dir_recursive(
                afc,
                &path,
                &remote_sub,
                uploaded,
                total,
                cb,
            ))
            .await?;
        } else if meta.file_type().is_symlink() {
            // Symlink: đọc target, tạo lại trên iPhone
            let target = tokio::fs::read_link(&path).await?;
            let target_str = target.to_string_lossy().to_string();
            println!("[afc] Symlink: {} -> {}", remote_sub, target_str);

            // AFC không hỗ trợ tạo symlink trực tiếp
            // Cách xử lý: tạo file rỗng cùng tên (thay vì symlink thật)
            // Trong thực tế, iOS sẽ resolve symlink khác — cần test
            let mut handle = afc
                .open(remote_sub.clone(), AfcFopenMode::WrOnly)
                .await?;
            handle.write_entire(target_str.as_bytes()).await?;
            handle.close().await?;
            *uploaded += target_str.len() as u64;
            cb((*uploaded as f64 / total * 100.0) as u64);
        } else {
            // File thường
            let mut handle = afc
                .open(remote_sub.clone(), AfcFopenMode::WrOnly)
                .await
                .with_context(|| format!("Mở remote file thất bại: {}", remote_sub))?;

            let bytes = tokio::fs::read(&path)
                .await
                .with_context(|| format!("Đọc local file thất bại: {}", path.display()))?;

            // Chunk 8KB
            for chunk in bytes.chunks(8 * 1024) {
                handle
                    .write_entire(chunk)
                    .await
                    .with_context(|| format!("Write chunk thất bại: {}", remote_sub))?;
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