// src/sideload/signer.rs
// Delegate signing sang zsign-rs

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;

/// Sign bundle tree — delegate sang zsign_signer module.
pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    _special: &Option<SpecialApp>,
) -> Result<()> {
    let bundle_dir = app.bundle.bundle_dir.clone();
    let output_ipa = std::env::temp_dir().join("fortiva_signed.ipa");

    // Gọi zsign-rs sign
    super::zsign_signer::sign_with_zsign(
        app,
        cert,
        profile_data,
        &bundle_dir,
        &output_ipa,
    )?;

    // Extract IPA signed ngược về bundle dir
    println!("[sign] Extract signed IPA back to bundle dir...");
    let parent = bundle_dir.parent()
        .ok_or_else(|| anyhow!("Bundle dir không có parent"))?;
    extract_ipa_to_dir(&output_ipa, parent)?;

    Ok(())
}

/// Extract IPA vào thư mục đích (giữ cấu trúc Payload/).
fn extract_ipa_to_dir(ipa_path: &Path, dest: &Path) -> Result<()> {
    use std::io::Read;

    let file = std::fs::File::open(ipa_path)
        .with_context(|| format!("Mở IPA fail: {}", ipa_path.display()))?;
    let mut zip = zip::ZipArchive::new(file)
        .context("Mở zip IPA fail")?;

    // Xóa Payload cũ
    let payload_dir = dest.join("Payload");
    if payload_dir.exists() {
        std::fs::remove_dir_all(&payload_dir)?;
    }

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        let out_path = dest.join(&name);

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            std::fs::write(&out_path, data)?;
        }
    }

    Ok(())
}
