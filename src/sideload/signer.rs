// src/sideload/signer.rs
use anyhow::{Context, Result};
use apple_codesign::cryptography::{InMemoryPrivateKey, PrivateKey};
use apple_codesign::{SigningSettings, UnifiedSigner};

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

    let _settings = SigningSettings::default();

    // Setup cert + chain
    let signing_key = build_signing_key(cert)?;
    let x509 = build_x509_cert(cert)?;

    let _settings = SigningSettings::default();
    settings.set_signing_key(signing_key.as_key_info_signer(), x509);
    settings.chain_apple_certificates();
    settings.set_team_id_from_signing_certificate();

    settings.set_for_notarization(false);
    settings.set_shallow(true);

    // Entitlements
    let team_id = extract_team_id(cert);
    let entitlements = extract_entitlements(profile_data, special, &team_id)?;

    let mut entitlements_xml: Vec<u8> = Vec::new();
    plist::to_writer_xml(
        &mut entitlements_xml,
        &plist::Value::Dictionary(entitlements),
    )
    .context("Encode entitlements XML thất bại")?;
    let entitlements_xml_str = String::from_utf8(entitlements_xml)?;

    settings
        .set_entitlements_xml(
            apple_codesign::SettingsScope::Main,
            entitlements_xml_str,
        )
        .context("Set entitlements XML thất bại")?;

    let signer = UnifiedSigner::new(settings);

    // Ký từng bundle sâu nhất trước
    let sorted_bundles = app.bundle.collect_bundles_sorted();

    for (i, bundle) in sorted_bundles.iter().enumerate() {
        let name = bundle
            .bundle_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("(unknown)");

        println!(
            "[sign] ({}/{}) {}",
            i + 1,
            sorted_bundles.len(),
            name
        );

        signer
            .sign_path_in_place(&bundle.bundle_dir)
            .with_context(|| format!("Ký thất bại: {}", bundle.bundle_dir.display()))?;
    }

    println!("[sign] ✅ Ký xong {} bundle", sorted_bundles.len());
    Ok(())
}

fn build_signing_key(cert: &CertificateIdentity) -> Result<InMemoryPrivateKey> {
    use apple_codesign::cryptography::InMemoryPrivateKey;
    use openssl::pkey::PKey;

    let pkey = PKey::private_key_from_pem(cert.key_pem.as_bytes())
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

    let cert_x509 = X509::from_pem(cert.cert_pem.as_bytes())
        .context("Parse cert PEM that bai")?;
    let cert_der = cert_x509
        .to_der()
        .context("Convert cert to DER that bai")?;

    x509_certificate::CapturedX509Certificate::from_der(cert_der)
        .context("Load cert from DER that bai")
}

fn extract_team_id(cert: &CertificateIdentity) -> String {
    if !cert.machine_id.is_empty() {
        return cert.machine_id.clone();
    }
    "UNKNOWN".to_string()
}
