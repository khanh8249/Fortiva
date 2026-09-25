// src/sideload/signer.rs
// Sign flow — pure selfsign (no zsign dependency)

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::selfsign;

pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    ext_profiles: &[(String, Vec<u8>)],
    _special: &Option<SpecialApp>,
) -> Result<()> {
    println!("[sign] === sign_app (selfsign) ===");

    let bundle_dir = app.bundle.bundle_dir.clone();
    if !bundle_dir.exists() {
        return Err(anyhow!("Bundle dir không tồn tại: {}", bundle_dir.display()));
    }

    // 0. Xóa SC_Info (FairPlay)
    let sc_info = bundle_dir.join("SC_Info");
    if sc_info.exists() {
        println!("[sign] Xóa SC_Info/");
        std::fs::remove_dir_all(&sc_info).ok();
    }

    // 1. Main bundle info
    let main_bundle_id = app.bundle.bundle_identifier()
        .ok_or_else(|| anyhow!("Main thiếu CFBundleIdentifier"))?
        .to_string();
    let main_exe_name = app.bundle.executable_name()
        .ok_or_else(|| anyhow!("Main thiếu CFBundleExecutable"))?
        .to_string();
    let main_exe = bundle_dir.join(&main_exe_name);

    println!("[sign] Main bundle: {}", main_bundle_id);
    println!("[sign] Main executable: {}", main_exe.display());

    // 2. Main info.plist
    let main_info_plist_path = bundle_dir.join("Info.plist");
    let main_info_plist = std::fs::read(&main_info_plist_path)
        .context("Đọc main Info.plist fail")?;

    // 3. Team ID từ cert (machine_id)
    let team_id = &cert.machine_id;

    // 4. Nhúng profile main vào bundle
    let main_profile_path = bundle_dir.join("embedded.mobileprovision");
    std::fs::write(&main_profile_path, profile_data)
        .context("Ghi main profile fail")?;
    println!("[sign] Ghi main profile: {} bytes", profile_data.len());

    // 5. Trích xuất entitlements từ profile main
    let main_entitlements = extract_entitlements_xml(profile_data)?;
    println!("[sign] Main entitlements: {} bytes", main_entitlements.len());

    // 6. Ký MAIN executable
    println!("[sign] Ký main executable...");
    selfsign::sign_binary_in_place(
        &main_exe,
        &main_bundle_id,
        team_id,
        &main_entitlements,
        Some(&main_info_plist),
        None,  // CodeResources hash (nếu có, ta sẽ build sau)
        cert,
    ).context("Sign main executable fail")?;
    println!("[sign] ✅ Main OK");

    // 7. Loop EXTENSIONS
    for ext in app.bundle.app_extensions() {
        let ext_bundle_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => continue,
        };
        let ext_exe_name = match ext.executable_name() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let ext_exe = ext.bundle_dir.join(&ext_exe_name);

        println!("[sign] Ext: {} ({})", ext_bundle_id, ext_exe.display());

        // 7a. Tìm profile riêng cho ext
        let ext_profile = ext_profiles.iter()
            .find(|(id, _)| id == &ext_bundle_id)
            .map(|(_, p)| p.as_slice())
            .unwrap_or(profile_data);  // fallback main profile

        // 7b. Nhúng profile vào ext
        let ext_profile_path = ext.bundle_dir.join("embedded.mobileprovision");
        std::fs::write(&ext_profile_path, ext_profile)
            .context("Ghi ext profile fail")?;

        // 7c. Trích xuất entitlements từ ext profile
        let ext_entitlements = extract_entitlements_xml(ext_profile)?;

        // 7d. Info.plist của ext
        let ext_info_plist_path = ext.bundle_dir.join("Info.plist");
        let ext_info_plist = std::fs::read(&ext_info_plist_path).ok();

        // 7e. Ký ext executable
        selfsign::sign_binary_in_place(
            &ext_exe,
            &ext_bundle_id,
            team_id,
            &ext_entitlements,
            ext_info_plist.as_deref(),
            None,
            cert,
        ).with_context(|| format!("Sign ext fail: {}", ext_bundle_id))?;

        println!("[sign] ✅ Ext OK: {}", ext_bundle_id);
    }

    println!("[sign] ✅ DONE");
    Ok(())
}

/// Extract entitlements XML từ profile (mobileprovision).
///
/// Profile là CMS wrapper, cần decode và lấy <plist> bên trong.
fn extract_entitlements_xml(profile_data: &[u8]) -> Result<Vec<u8>> {
    use plist::Value;

    // Tìm <plist>...</plist> trong CMS
    let start = find_subsequence(profile_data, b"<plist");
    let end = rfind_subsequence(profile_data, b"</plist>");

    let (start, end) = match (start, end) {
        (Some(s), Some(e)) => (s, e + b"</plist>".len()),
        _ => return Err(anyhow!("Không tìm thấy <plist> trong profile")),
    };

    let plist_data = &profile_data[start..end];
    let plist: Value = plist::from_bytes(plist_data)
        .context("Parse profile plist fail")?;

    let entitlements = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Profile plist không phải dict"))?
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("Profile thiếu Entitlements"))?;

    // Re-serialize entitlements dict → XML bytes
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(entitlements.clone()))
        .context("Serialize entitlements XML fail")?;

    Ok(buf)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
