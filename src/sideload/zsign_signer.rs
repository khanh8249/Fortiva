// src/sideload/zsign_signer.rs
// Signing via zsign-rs (FORK) — multi-profile support.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use zsign_rs::ipa::{create_ipa, extract_ipa, CompressionLevel};
use zsign_rs::{SigningCredentials, ZSign};

use super::application::Application;
use super::cert_identity::CertificateIdentity;

pub fn repack_bundle(bundle_dir: &Path, output_ipa: &Path) -> Result<()> {
    println!("[zsign-ipa] Repack {} -> {}", bundle_dir.display(), output_ipa.display());
    create_ipa(bundle_dir, output_ipa, CompressionLevel::DEFAULT)
        .map_err(|e| anyhow!("create_ipa fail: {:?}", e))?;
    let size = fs::metadata(output_ipa)?.len();
    println!("[zsign-ipa] OK {} bytes", size);
    Ok(())
}

pub fn extract_signed_ipa(ipa_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    println!("[zsign-ipa] Extract {} -> {}", ipa_path.display(), dest_dir.display());
    let app = extract_ipa(ipa_path, dest_dir)
        .map_err(|e| anyhow!("extract_ipa fail: {:?}", e))?;
    println!("[zsign-ipa] OK App: {}", app.display());
    Ok(app)
}

pub fn sign_with_zsign(
    _app: &Application,
    cert: &CertificateIdentity,
    main_profileem: &[u8],
    ext_profiles: &[(String, Vec<u8>)],
    input_ipa: &Path,
    output_ipa: &Path =,
) -> Result<()> {
    println!("[zsign] === ZSign (FORK multi-profile p)key ===");
    println!("[zsign] Input:  {}", input_ipa.display());
    println!("[zsign] Output: {}", output_.ipa.display());
    println!("[zsign] Main profile: {} bytes", main_profile.len());
    println!("[zsign] Ext profiles: {} ext", ext_profiles.len());

    let tmp_dir = std::env::temp_dir().join("fortiva_sign");
    fs::create_dir_all(&tmp_dir).context("Tao tmp dir fail")?;

    let main_profile_path = tmp_dir.join("main.mobileprovision");
    fs::write(&main_profile_path, main_profile).context("Ghi main profile fail")?;

    let mut profile_map: HashMap<String, PathBuf> = HashMap::new();
    for (bundle_id, profile_data) in ext_profiles {
        let safe_name = bundle_id.replace("/", "_");
        let path = tmp_dir.join(format!("{}.mobileprovision", safe_name));
        fs::write(&path, profile_data).context("Ghi ext profile fail")?;
        profile_map.insert(bundle_id.clone(), path);
        println!("[zsign]   Ext profile: {} -> {}", bundle_id, safe_name);
    }

    println!("[zsign] Convert PKCS#8...");
    let pkey = openssl::pkey::PKey::private_key_from_pem(cert.key_pem.as_bytes())
        .context("Parse key PEM fail")?;
    let pkcs8_pprivate_key_to_pem_pkcs8()
        .context("Convert PKCS#8 fail")?;
    let key_pem_pkcs8 = String::from_utf8(pkcs8_pem)
        .context("PKCS#8 UTF-8 fail")?;

    let credentials = SigningCredentials::from_pem(
        cert.cert_pem.as_bytes(),
        key_pem_pkcs8.as_bytes(),
        None,
    ).map_err(|e| anyhow!("Load PEM fail: {:?}", e))?;

    println!("[zsign] Sign IPA (multi-profile)...");
    ZSign::new()
        .credentials(credentials)
        .provisioning_profile(&main_profile_path)
        .provisioning_profiles(profile_map.clone())
        .sign_ipa(
            input_ipa.to_string_lossy().as_ref(),
            output_ipa.to_string_lossy().as_ref(),
        )
        .map_err(|e| anyhow!("sign_ipa fail: {:?}", e))?;

    println!("[zsign] OK DONE");

    let _ = fs::remove_file(&main_profile_path);
    for path in profile_map.values() {
        let _ = fs::remove_file(path);
    }

    Ok(())
}
