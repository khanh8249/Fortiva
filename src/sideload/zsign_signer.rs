// src/sideload/zsign_signer.rs
// Signing via zsign-rs (IpaSigner) — tự động extract + ký + repack

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

use zsign_rs::{SigningCredentials, ZSign};

use super::application::Application;
use super::cert_identity::CertificateIdentity;

/// Sign IPA dùng zsign-rs.
///
/// Flow:
/// 1. Repack bundle tree đã patch → IPA tạm
/// 2. Ghi profile tạm
/// 3. Gọi ZSign::sign_ipa() → output IPA (đã nhúng entitlements)
/// 4. Trả về path output IPA
pub fn sign_with_zsign(
    app: &Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    bundle_dir: &Path,
    output_ipa: &Path,
) -> Result<()> {
    println!("[zsign] === zsign-rs signing ===");

    // 1. Repack bundle tree → IPA tạm
    let tmp_ipa = std::env::temp_dir().join("fortiva_input.ipa");
    println!("[zsign] Repack bundle → {}", tmp_ipa.display());
    repack_bundle_to_ipa(bundle_dir, &tmp_ipa)?;
    println!("[zsign] IPA tạm: {} bytes", fs::metadata(&tmp_ipa)?.len());

    // 2. Ghi profile tạm
    let tmp_dir = std::env::temp_dir().join("fortiva_sign");
    fs::create_dir_all(&tmp_dir).context("Tạo tmp dir fail")?;


    let profile_path = tmp_dir.join("app.mobileprovision");
    fs::write(&profile_path, profile_data).context("Ghi profile fail")?;
    println!("[zsign] Profile: {} ({} bytes)", profile_path.display(), profile_data.len());

    // 3. Load credentials
    // 2. Convert key PKCS#1 → PKCS#8 (Apple thường trả PKCS#1)
    println!("[zsign] Chuẩn bị credentials từ PEM...");
    let pkey = openssl::pkey::PKey::private_key_from_pem(cert.key_pem.as_bytes())
        .context("Parse key PEM fail")?;
    let pkcs8_pem = pkey.private_key_to_pem_pkcs8()
        .context("Convert PKCS#8 fail")?;
    let key_pem_pkcs8 = String::from_utf8(pkcs8_pem)
        .context("PKCS#8 UTF-8 fail")?;

    let credentials = SigningCredentials::from_pem(
        cert.cert_pem.as_bytes(),
        key_pem_pkcs8.as_bytes(),
        None,
    ).map_err(|e| anyhow!("Load PEM fail: {:?}", e))?;

    // 4. Sign IPA
    println!("[zsign] Sign IPA → {}", output_ipa.display());
    ZSign::new()
        .credentials(credentials)
        .provisioning_profile(profile_path.to_string_lossy().as_ref())
        .sign_ipa(
            tmp_ipa.to_string_lossy().as_ref(),
            output_ipa.to_string_lossy().as_ref(),
        )
        .map_err(|e| anyhow!("zsign sign_ipa fail: {:?}", e))?;

    println!("[zsign] ✅ DONE — {}", output_ipa.display());

    // Cleanup
    let _ = fs::remove_file(&tmp_ipa);
    let _ = fs::remove_file(&profile_path);

    let _ = app; // dùng để tránh warning unused
    Ok(())
}

/// Repack thư mục .app thành IPA (chỉ cần file, không cần symlink phức tạp).
fn repack_bundle_to_ipa(bundle_dir: &Path, output_ipa: &Path) -> Result<()> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use walkdir::WalkDir;

    let bundle_name = bundle_dir
        .file_name()
        .ok_or_else(|| anyhow!("Bundle dir không có tên"))?
        .to_string_lossy()
        .to_string();

    let file = fs::File::create(output_ipa)
        .with_context(|| format!("Tạo IPA fail: {}", output_ipa.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let base_parent = bundle_dir.parent()
        .ok_or_else(|| anyhow!("Bundle dir không có parent"))?;

    for entry in WalkDir::new(bundle_dir).follow_links(false) {
        let entry = entry.context("Walk bundle fail")?;
        let path = entry.path();

        // Relative từ bundle.parent(): "Payload/SideStore.app/..."
        let rel = path.strip_prefix(base_parent)
            .with_context(|| format!("Strip prefix fail: {}", path.display()))?;

        // Đảm bảo có "Payload/" prefix (nếu chưa)
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let full_path = if rel_str.starts_with("Payload/") {
            rel_str.to_string()
        } else {
            format!("Payload/{}", rel_str)
        };

        if path.is_file() {
            zip.start_file(&full_path, opts)
                .with_context(|| format!("Zip start_file fail: {}", full_path))?;
            let data = fs::read(path)
                .with_context(|| format!("Đọc file fail: {}", path.display()))?;
            zip.write_all(&data)?;
        } else if path.is_dir() {
            // Không cần add_dir — zip tự tạo khi có file
            // Nhưng cần cho thư mục rỗng
            zip.add_directory(&full_path, opts)
                .with_context(|| format!("Zip add_dir fail: {}", full_path))?;
        }
    }

    zip.finish().context("Zip finish fail")?;
    let _ = bundle_name;
    Ok(())
}