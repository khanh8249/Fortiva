// src/sideload/signer.rs
use anyhow::{Context, Result};
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

    let mut settings = SigningSettings::default();

    // Setup cert + chain
    setup_signing_settings(&mut settings, cert)?;

    settings.set_for_notarization(false);
    settings.set_shallow(true);

    // Entitlements
    let team_id = extract_team_id(cert);
    let entitlements = extract_entitlements(profile_data, special, &team_id)?;

    let entitlements_xml = plist::to_formatted_writer(
        &mut Vec::new(),
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

fn setup_signing_settings(
    settings: &mut SigningSettings,
    cert: &CertificateIdentity,
) -> Result<()> {
    use apple_codesign::cryptography::{InMemoryPrivateKey, PrivateKey};

    let signing_key = InMemoryPrivateKey::from_pem(
        &cert.key_pem,
        None,
    )
    .context("Load private key thất bại")?;

    let x509 = x509_certificate::CapturedX509Certificate::from_pem(&cert.cert_pem)
        .context("Load cert PEM thất bại")?;

    settings.set_signing_key(
        signing_key.as_key_info_signer(),
        x509,
    );
    settings.chain_apple_certificates();
    settings.set_team_id_from_signing_certificate();

    Ok(())
}

fn extract_team_id(cert: &CertificateIdentity) -> String {
    if !cert.machine_id.is_empty() {
        return cert.machine_id.clone();
    }
    "UNKNOWN".to_string()
}