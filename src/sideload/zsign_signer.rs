// src/sideload/zsign_signer.rs
// Signing via zsign-core — pure Rust, WASM-compatible

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

use zsign_core::codesign::{CodeDirectoryBuilder, SuperBlobBuilder};
use zsign_core::crypto::SigningCredentials;
use zsign_core::macho::MachO;
use zsign_core::provisioning::extract_entitlements_from_profile;

use super::application::Application;
use super::cert_identity::CertificateIdentity;

/// Sign toàn bộ bundle tree dùng zsign-core.
pub fn sign_app_with_zsign(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
) -> Result<()> {
    println!("[zsign] === zsign-core signing ===");

    // 1. Load credentials từ P12
    let p12_bytes = cert.as_p12(&cert.machine_id)
        .context("Tạo P12 fail")?;
    let credentials = SigningCredentials::from_p12(&p12_bytes, "")
        .map_err(|e| anyhow!("Load P12 fail: {:?}", e))?;
    println!("[zsign] Team ID: {:?}", credentials.team_id);

    // 2. Extract entitlements XML từ profile
    let entitlements_xml = extract_entitlements_from_profile(profile_data)
        .map_err(|e| anyhow!("Extract entitlements fail: {:?}", e))?
        .ok_or_else(|| anyhow!("Profile không có Entitlements"))?;
    println!("[zsign] Entitlements: {} bytes", entitlements_xml.len());

    // 3. Main bundle ID (đã patch ở bước trước)
    let main_bundle_id = app.bundle.bundle_identifier()
        .ok_or_else(|| anyhow!("Main app thiếu CFBundleIdentifier"))?
        .to_string();
    println!("[zsign] Main bundle ID: {}", main_bundle_id);

    // 4. Walk bundle tree — ký ext/frameworks trước (depth-first)
    let extensions = app.bundle.app_extensions();
    for ext in extensions {
        let ext_id = ext.bundle_identifier()
            .ok_or_else(|| anyhow!("Ext thiếu CFBundleIdentifier"))?
            .to_string();
        let ext_exe = ext.executable_name()
            .ok_or_else(|| anyhow!("Ext thiếu CFBundleExecutable: {}", ext_id))?
            .to_string();
        let ext_exe_path = ext.bundle_dir.join(&ext_exe);

        println!("[zsign] Sign ext: {} ({})", ext_id, ext_exe_path.display());

        sign_binary(&ext_exe_path, &ext_id, &entitlements_xml, &credentials)?;
    }

    // 5. Ký main binary (sau cùng)
    let main_exe = app.bundle.executable_name()
        .ok_or_else(|| anyhow!("Main app thiếu CFBundleExecutable"))?
        .to_string();
    let main_exe_path = app.bundle.bundle_dir.join(&main_exe);

    println!("[zsign] Sign main: {} ({})", main_bundle_id, main_exe_path.display());
    sign_binary(&main_exe_path, &main_bundle_id, &entitlements_xml, &credentials)?;

    println!("[zsign] ✅ DONE");
    Ok(())
}

/// Ký 1 binary: build CodeDirectory → assemble SuperBlob → inject.
fn sign_binary(
    binary_path: &Path,
    bundle_id: &str,
    entitlements_xml: &[u8],
    credentials: &SigningCredentials,
) -> Result<()> {
    // 1. Đọc binary
    let macho_bytes = fs::read(binary_path)
        .with_context(|| format!("Đọc binary fail: {}", binary_path.display()))?;

    // 2. Parse Mach-O
    let macho = MachO::parse(&macho_bytes)
        .map_err(|e| anyhow!("Parse Mach-O fail: {:?}", e))?;

    // 3. Build CodeDirectory SHA-1 + SHA-256
    let team = credentials.team_id.as_deref().unwrap_or("");

    let cd_sha1 = CodeDirectoryBuilder::new(bundle_id, &macho_bytes)
        .team_id(team)
        .entitlements(entitlements_xml)
        .build_sha1();

    let cd_sha256 = CodeDirectoryBuilder::new(bundle_id, &macho_bytes)
        .team_id(team)
        .entitlements(entitlements_xml)
        .build_sha256();

    // 4. Assemble SuperBlob
    let superblob = SuperBlobBuilder::new()
        .code_directory_sha1(cd_sha1)
        .code_directory_sha256(cd_sha256)
        .entitlements(entitlements_xml.to_vec())
        .bundle_id(bundle_id)
        .build();

    // 5. Inject signature
    let signed_bytes = macho.replace_code_signature(&superblob)
        .map_err(|e| anyhow!("Replace code signature fail: {:?}", e))?;

    // 6. Ghi lại binary
    fs::write(binary_path, &signed_bytes)
        .with_context(|| format!("Ghi binary fail: {}", binary_path.display()))?;

    println!("[zsign]   ✅ {} ({} bytes)",
             binary_path.file_name().unwrap_or_default().to_string_lossy(),
             signed_bytes.len());
    Ok(())
}
