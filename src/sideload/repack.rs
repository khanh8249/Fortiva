// src/sideload/repack.rs
use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::write::FileOptions;

/// Repack bundle directory thanh IPA file.
/// Input:  /tmp/xxx/Payload/App.app
/// Output: /tmp/xxx/App.signed.ipa
pub fn repack_ipa(bundle_dir: &Path) -> Result<PathBuf> {
    // 1. Tim Payload/ parent
    let payload_dir = bundle_dir.parent()
        .ok_or_else(|| anyhow!("Khong co parent cho bundle_dir"))?;

    // 2. Verify la Payload/
    if payload_dir.file_name().and_then(|s| s.to_str()) != Some("Payload") {
        return Err(anyhow!(
            "Bundle dir khong nam trong Payload/: {}",
            bundle_dir.display()
        ));
    }

    // 3. Root = thu muc chua Payload/
    let root = payload_dir.parent()
        .ok_or_else(|| anyhow!("Khong co parent cho Payload/"))?;

    // 4. Verify root co Payload/
    let has_payload = std::fs::read_dir(root)?
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_str() == Some("Payload"));

    if !has_payload {
        return Err(anyhow!("Root khong chua Payload/"));
    }

    // 5. Output path
    let app_name = bundle_dir.file_name()
        .ok_or_else(|| anyhow!("Bundle khong co ten"))?
        .to_string_lossy()
        .trim_end_matches(".app")
        .to_string();

    let output_path = root.join(format!("{}.signed.ipa", app_name));

    println!("[repack] Bundle: {}", bundle_dir.display());
    println!("[repack] Root:   {}", root.display());
    println!("[repack] Output: {}", output_path.display());

    // 6. Xoa file cu neu co
    if output_path.exists() {
        std::fs::remove_file(&output_path)?;
    }

    // 7. Tao ZIP
    let file = File::create(&output_path)
        .with_context(|| format!("Tao file fail: {}", output_path.display()))?;
    let mut zip = zip::ZipWriter::new(file);

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    // 8. Walk chi tu root
    let mut file_count = 0;
    let mut dir_count = 0;

    for entry in WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let rel_path = path.strip_prefix(root)
            .context("Strip prefix fail")?;

        // Chuyen Windows path -> Unix path
        let name = rel_path.to_string_lossy().replace("\\", "/");

        if path.is_file() {
            zip.start_file(&name, options)
                .with_context(|| format!("Add file fail: {}", name))?;

            let mut f = File::open(path)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            zip.write_all(&buf)?;
            file_count += 1;
        } else if path.is_dir() && !name.is_empty() {
            zip.add_directory(&name, options)
                .with_context(|| format!("Add dir fail: {}", name))?;
            dir_count += 1;
        }
    }

    zip.finish().context("Finish zip fail")?;

    let size = std::fs::metadata(&output_path)?.len();
    println!(
        "[repack] OK: {} files, {} dirs, {} bytes",
        file_count, dir_count, size
    );

    Ok(output_path)
}
