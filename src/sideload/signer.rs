// src/sideload/signer.rs
use anyhow::{anyhow, Context, Result};
use apple_codesign::cryptography::{InMemoryPrivateKey, PrivateKey};
use apple_codesign::{SettingsScope, SigningSettings, UnifiedSigner};
use plist::{Dictionary, Value};

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::entitlements::extract_entitlements;

// ============================================================
//  SIGN BUNDLE — isideload style
// ============================================================

/// Ký bundle tree với:
/// - Certificate chain từ profile (qua Apple WWDR + Root)
/// - Entitlements cho main + ext
/// - Profile riêng cho main + ext
/// - sign_bundle() tự động walk nested bundles
pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    special: &Option<SpecialApp>,
) -> Result<()> {
    println!("[sign] Chuẩn bị SigningSettings...");

    // 1. Setup cert
    let signing_key = build_signing_key(cert)?;
    let x509 = build_x509_cert(cert)?;

    let mut settings = SigningSettings::default();
    settings.set_signing_key(signing_key.as_key_info_signer(), x509);
    settings.chain_apple_certificates();
    settings.set_team_id_from_signing_certificate();
    settings.set_for_notarization(false);
    settings.set_shallow(true);

    // 2. Entitlements cho main
    let team_id = extract_team_id(cert);
    
    // Lấy bundle ID MỚI của main app (đã patch)
    let main_bundle_id = app.bundle.bundle_identifier()
        .ok_or_else(|| anyhow!("Main app thiếu CFBundleIdentifier"))?
        .to_string();
    
    // ⚠️ FIX: Set identifier trước khi set entitlements
    settings.set_identifier(&main_bundle_id)
        .context("Set identifier fail")?;
    println!("[sign] Identifier: {}", main_bundle_id);
    
    // ⚠️ FIX: Lấy tên executable để set entitlements cho binary
    let main_exe_name = app.bundle.executable_name()?
        .to_string();
    println!("[sign] Main executable: {}", main_exe_name);
    
    let main_entitlements = extract_entitlements(
        profile_data, 
        special, 
        &team_id,
        &main_bundle_id,
    ).context("Extract main entitlements fail")?;
    let main_xml = dict_to_xml_string(&main_entitlements)?;

    // Set cho Main scope (metadata)
    settings
        .set_entitlements_xml(SettingsScope::Main, main_xml.clone())
        .context("Set main entitlements (Main) fail")?;
    
    // ⚠️ FIX: Set cho BINARY PATH — đây là cái iOS check thực sự
    settings
        .set_entitlements_xml(
            SettingsScope::Path(main_exe_name.clone()),
            main_xml.clone(),
        )
        .context("Set main entitlements (Path) fail")?;

    println!("[sign] Main entitlements OK ({} keys)", main_entitlements.len());

    // 3. Entitlements riêng cho ext (SettingsScope::Path)
    let extensions = app.bundle.app_extensions();
    let mut ext_count = 0;

    for ext in extensions {
        let ext_bundle_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => continue,
        };

        let ext_rel_path = match ext.bundle_dir.strip_prefix(&app.bundle.bundle_dir) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // Clone entitlements + override app-id
        let mut ext_entitlements = main_entitlements.clone();
        let ext_app_id = format!("{}.{}", team_id, ext_bundle_id);
        ext_entitlements.insert(
            "application-identifier".to_string(),
            Value::String(ext_app_id.clone()),
        );

        if let Some(Value::Array(groups)) = ext_entitlements.get_mut("keychain-access-groups") {
            if !groups.is_empty() {
                groups[0] = Value::String(ext_app_id.clone());
            }
        }

        let ext_xml = dict_to_xml_string(&ext_entitlements)?;

        settings
            .set_entitlements_xml(SettingsScope::Path(ext_rel_path.clone()), ext_xml.clone())
            .with_context(|| format!("Set ext entitlements (bundle) fail: {}", ext_bundle_id))?;
        
        let ext_exe_name = ext.executable_name()
            .ok_or_else(|| anyhow!("Ext thiếu CFBundleExecutable: {}", ext_bundle_id))?;
        let ext_exe_rel = format!("{}/{}", ext_rel_path, ext_exe_name);
        
        settings
            .set_entitlements_xml(SettingsScope::Path(ext_exe_rel.clone()), ext_xml)
            .with_context(|| format!("Set ext entitlements (binary) fail: {}", ext_bundle_id))?;

        println!("[sign] Ext entitlements OK: {}", ext_bundle_id);
        ext_count += 1;
    }

    if ext_count > 0 {
        println!("[sign] Đã set entitlements cho {} extension", ext_count);
    }

    // 4. Xóa _CodeSignature CŨ (nếu có) — tránh hash mismatch
    cleanup_code_signatures(app)?;

    // 5. Verify profiles nhúng (bắt buộc trước khi sign)
    verify_profiles(app)?;

    // 5. SIGN — dùng sign_bundle() với temp output
    let signer = UnifiedSigner::new(settings);

    let main_bundle = app.bundle.bundle_dir.clone();
    let temp_output = main_bundle.with_extension("app.signed_tmp");

    println!("[sign] Sign bundle → temp...");
    println!("[sign] Input:  {}", main_bundle.display());
    println!("[sign] Output: {}", temp_output.display());

    // Xóa temp nếu có
    if temp_output.exists() {
        std::fs::remove_dir_all(&temp_output)?;
    }

    signer
        .sign_bundle(&main_bundle, &temp_output)
        .context("sign_bundle fail")?;

    println!("[sign] ✅ Sign OK — move về chỗ cũ");

    // 6. Move temp → main (in-place)
    std::fs::remove_dir_all(&main_bundle)?;
    std::fs::rename(&temp_output, &main_bundle)?;

    println!("[sign] ✅ DONE");
    Ok(())
}

// ============================================================
//  VERIFY PROFILES
// ============================================================

fn verify_profiles(app: &Application) -> Result<()> {
    // Main
    let main_prov = app.bundle.bundle_dir.join("embedded.mobileprovision");
    if !main_prov.exists() {
        return Err(anyhow!(
            "Main thiếu embedded.mobileprovision — nhúng trước khi sign!"
        ));
    }
    let size = std::fs::metadata(&main_prov)?.len();
    println!("[verify] ✅ Main profile ({} bytes)", size);

    // Extensions
    for ext in app.bundle.app_extensions() {
        let ext_id = ext.bundle_identifier().unwrap_or("?");
        let ext_prov = ext.bundle_dir.join("embedded.mobileprovision");

        if !ext_prov.exists() {
            return Err(anyhow!(
                "Extension {} thiếu embedded.mobileprovision!",
                ext_id
            ));
        }
        let size = std::fs::metadata(&ext_prov)?.len();
        println!("[verify] ✅ Ext profile {} ({} bytes)", ext_id, size);
    }

    Ok(())
}

// ============================================================
//  HELPERS
// ============================================================

fn dict_to_xml_string(dict: &Dictionary) -> Result<String> {
    let mut xml_bytes: Vec<u8> = Vec::new();
    plist::to_writer_xml(&mut xml_bytes, &Value::Dictionary(dict.clone()))
        .context("Encode entitlements XML fail")?;
    String::from_utf8(xml_bytes).context("Entitlements XML không phải UTF-8")
}

fn build_signing_key(cert: &CertificateIdentity) -> Result<InMemoryPrivateKey> {
    use openssl::pkey::PKey;

    let pkey = PKey::private_key_from_pem(cert.key_pem.as_bytes())
        .context("Parse private key PEM fail")?;
    let pkcs8_der = pkey
        .private_key_to_pkcs8()
        .context("Convert key to PKCS#8 DER fail")?;

    InMemoryPrivateKey::from_pkcs8_der(&pkcs8_der)
        .context("Load private key fail")
}

fn build_x509_cert(
    cert: &CertificateIdentity,
) -> Result<x509_certificate::CapturedX509Certificate> {
    use openssl::x509::X509;

    let cert_x509 = X509::from_pem(cert.cert_pem.as_bytes())
        .context("Parse cert PEM fail")?;
    let cert_der = cert_x509.to_der().context("Convert cert to DER fail")?;

    x509_certificate::CapturedX509Certificate::from_der(cert_der)
        .context("Load cert from DER fail")
}

fn extract_team_id(cert: &CertificateIdentity) -> String {
    if !cert.machine_id.is_empty() {
        return cert.machine_id.clone();
    }
    "UNKNOWN".to_string()
}

// ============================================================
//  CLEANUP _CodeSignature CŨ
// ============================================================

/// Xóa tất cả _CodeSignature cũ trong bundle tree.
/// Tránh hash mismatch khi sign.
fn cleanup_code_signatures(app: &Application) -> Result<()> {
    let mut count = 0;

    // 1. Main bundle
    let main_cs = app.bundle.bundle_dir.join("_CodeSignature");
    if main_cs.exists() {
        std::fs::remove_dir_all(&main_cs)
            .with_context(|| format!("Xóa main _CodeSignature fail: {}", main_cs.display()))?;
        println!("[sign] 🗑️  Xóa main _CodeSignature");
        count += 1;
    }

    // 2. Extensions
    for ext in app.bundle.app_extensions() {
        let ext_cs = ext.bundle_dir.join("_CodeSignature");
        if ext_cs.exists() {
            std::fs::remove_dir_all(&ext_cs)
                .with_context(|| format!("Xóa ext _CodeSignature fail: {}", ext_cs.display()))?;
            let name = ext.bundle_dir.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?");
            println!("[sign] 🗑️  Xóa ext _CodeSignature: {}", name);
            count += 1;
        }
    }

    // 3. Frameworks (nếu có)
    // (Đã bao gồm trong collect_bundles_sorted nếu cần)

    println!("[sign] Đã xóa {} _CodeSignature cũ", count);
    Ok(())
}