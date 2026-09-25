// src/sideload/signer.rs
// Sign flow — delegate to zsign-rs fork

use anyhow::{anyhow, Context, Result};

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::zsign_signer;

pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    ext_profiles: &[(String, Vec<u8>)],
    _special: &Option<SpecialApp>,
) -> Result<()> {
    println!("[sign] === sign_app (zsign-rs fork) ===");

    let bundle_dir = app.bundle.bundle_dir.clone();
    if !bundle_dir.exists() {
        return Err(anyhow!("Bundle dir khong ton tai: {}", bundle_dir.display()));
    }

    let sc_info = bundle_dir.join("SC_Info");
    if sc_info.exists() {
        println!("[sign] Xoa SC_Info/");
        std::fs::remove_dir_all(&sc_info).ok();
    }

    let tmp_ipa = std::env::temp_dir().join("fortiva_input.ipa");
    if tmp_ipa.exists() { std::fs::remove_file(&tmp_ipa).ok(); }
    zsign_signer::repack_bundle(&bundle_dir, &tmp_ipa)?;

    let output_ipa = std::env::temp_dir().join("fortiva_signed.ipa");
    if output_ipa.exists() { std::fs::remove_file(&output_ipa).ok(); }
    zsign_signer::sign_with_zsign(
        app, cert, profile_data, ext_profiles, &tmp_ipa, &output_ipa,
    )?;

    let tmp_extract = std::env::temp_dir().join("fortiva_signed_extract");
    if tmp_extract.exists() { std::fs::remove_dir_all(&tmp_extract).ok(); }
    std::fs::create_dir_all(&tmp_extract).context("Tao tmp_extract fail")?;

    let extracted_app = zsign_signer::extract_signed_ipa(&output_ipa, &tmp_extract)?;
    println!("[sign] Extracted: {}", extracted_app.display());

    if bundle_dir.exists() {
        std::fs::remove_dir_all(&bundle_dir)
            .with_context(|| format!("Xoa bundle cu fail: {}", bundle_dir.display()))?;
    }
    std::fs::rename(&extracted_app, &bundle_dir)
        .with_context(|| format!(
            "Move bundle fail: {} -> {}",
            extracted_app.display(), bundle_dir.display()
        ))?;

    let _ = std::fs::remove_dir_all(&tmp_extract);
    let _ = std::fs::remove_file(&tmp_ipa);

    println!("[sign] OK DONE — {}", bundle_dir.display());
    Ok(())
}
