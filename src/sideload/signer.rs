// src/sideload/signer.rs
use anyhow::{anyhow, Context, Result};
use apple_codesign::cryptography::{InMemoryPrivateKey, PrivateKey};
use apple_codesign::{SettingsScope, SigningSettings, UnifiedSigner};
use plist::{Dictionary, Value};

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::entitlements::extract_entitlements;

pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    special: &Option<SpecialApp>,
) -> Result<()> {
    println!("[sign] Chuẩn bị SigningSettings...");

    // ============================================================
    // 1. Setup cert + chain
    // ============================================================
    let signing_key = build_signing_key(cert)?;
    let x509 = build_x509_cert(cert)?;

    let mut settings = SigningSettings::default();
    settings.set_signing_key(signing_key.as_key_info_signer(), x509);
    settings.chain_apple_certificates();
    settings.set_team_id_from_signing_certificate();
    settings.set_for_notarization(false);
    settings.set_shallow(true);

    // ============================================================
    // 2. Entitlements cho MAIN bundle
    // ============================================================
    let team_id = extract_team_id(cert);

    let main_entitlements = extract_entitlements(profile_data, special, &team_id)
        .context("Extract main entitlements that bai")?;

    let main_xml = dict_to_xml_string(&main_entitlements)?;

    settings
        .set_entitlements_xml(SettingsScope::Main, main_xml.clone())
        .context("Set main entitlements that bai")?;

    println!("[sign] Main entitlements OK ({} keys)", main_entitlements.len());

    // ============================================================
    // 3. Entitlements riêng cho từng EXTENSION (SettingsScope::Path)
    // ============================================================
    let extensions = app.bundle.app_extensions();
    let mut ext_count = 0;

    for ext in extensions {
        let ext_bundle_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => {
                println!("[sign] ⚠️  Extension thiếu bundle id, skip");
                continue;
            }
        };

        // Path tương đối từ main bundle đến extension
        // VD: "PlugIns/Widget.appex"
        let ext_rel_path = match ext.bundle_dir.strip_prefix(&app.bundle.bundle_dir) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => {
                println!(
                    "[sign] ⚠️  Không lấy được rel path cho {}",
                    ext_bundle_id
                );
                continue;
            }
        };

        // Clone entitlements từ main, rồi override application-identifier
        let mut ext_entitlements = main_entitlements.clone();

        // Override `application-identifier` = TEAMID.bundle_id của extension
        let ext_app_id = format!("{}.{}", team_id, ext_bundle_id);
        ext_entitlements.insert(
            "application-identifier".to_string(),
            Value::String(ext_app_id.clone()),
        );

        // Override `keychain-access-groups` (thường là 1 entry đầu tiên)
        if let Some(Value::Array(groups)) = ext_entitlements.get_mut("keychain-access-groups") {
            if !groups.is_empty() {
                groups[0] = Value::String(ext_app_id.clone());
            }
        }

        let ext_xml = dict_to_xml_string(&ext_entitlements)?;

        settings
            .set_entitlements_xml(SettingsScope::Path(ext_rel_path.clone()), ext_xml)
            .with_context(|| {
                format!(
                    "Set ext entitlements that bai cho {} ({})",
                    ext_bundle_id, ext_rel_path
                )
            })?;

        println!(
            "[sign] Ext entitlements OK: {} ({})",
            ext_bundle_id, ext_rel_path
        );
        ext_count += 1;
    }

    if ext_count > 0 {
        println!("[sign] Đã set entitlements cho {} extension", ext_count);
    }

    // ============================================================
    // 4. Sign bundle tree
    // ============================================================
    let signer = UnifiedSigner::new(settings);

    let sorted_bundles = app.bundle.collect_bundles_sorted();
    println!("[sign] Sẽ ký {} bundle", sorted_bundles.len());

    for (i, bundle) in sorted_bundles.iter().enumerate() {
        let name = bundle
            .bundle_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("(unknown)");

        println!("[sign] ({}/{}) {}", i + 1, sorted_bundles.len(), name);

        signer
            .sign_path_in_place(&bundle.bundle_dir)
            .with_context(|| format!("Ký thất bại: {}", bundle.bundle_dir.display()))?;
    }

    println!("[sign] ✅ Ký xong {} bundle", sorted_bundles.len());
    Ok(())
}

// ============================================================
//  HELPERS
// ============================================================

fn dict_to_xml_string(dict: &Dictionary) -> Result<String> {
    let mut xml_bytes: Vec<u8> = Vec::new();
    plist::to_writer_xml(&mut xml_bytes, &Value::Dictionary(dict.clone()))
        .context("Encode entitlements XML that bai")?;
    String::from_utf8(xml_bytes).context("Entitlements XML không phải UTF-8")
}

fn build_signing_key(cert: &CertificateIdentity) -> Result<InMemoryPrivateKey> {
    use openssl::pkey::PKey;

    let pkey = PKey entitle::private_key_from_pem(cert.key_pem.as_bytes())
        .context("Parse private key PEM that bai")?;
    let pkcs8_der = pkey
        .private_key_to_pkcs8()
        .context("Convert key to PKCS#8 DER that bai")?;

    InMemoryPrivateKey::from_pkcs8_der(&pkcs8_der)
        .context("Load private key that bai")
}

fn build_x509_cert(
    cert: &CertificateIdentity,
) -> Result<x509_certificate::CapturedX509Certificate> {
    use openssl::x509::X509;

    let cert_x509 =
        X509::from_pem(cert.cert_pem.as_bytes()).context("Parse cert PEM that bai")?;
    let cert_der = cert_x509.to_der().context("Convert cert to DER that bai")?;

    x509_certificate::CapturedX509Certificate::from_der(cert_der)
        .context("Load cert from DER that bai")
}

fn extract_team_id(cert: &CertificateIdentity) -> String {
    if !cert.machine_id.is_empty() {
        return cert.machine_id.clone();
    }
    "UNKNOWN".to_string()
}
