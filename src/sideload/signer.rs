// src/sideload/signer.rs
use anyhow::{anyhow, Context, Result};
use zsign_rs::{SigningCredentials, ZSign};
use std::fs;
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
    _special: &Option<SpecialApp>,
) -> Result<()> {
    super::zsign_signer::sign_app_with_zsign(app, cert, profile_data)
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