use anyhow::{anyhow, Context, Result};
use std::path::Path;

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::selfsign;

fn sign_bundle_with_cr(
    bundle_dir: &Path,
    binary_path: &Path,
    bundle_id: &str,
    team_id: &str,
    entitlements_xml: &[u8],
    info_plist: Option<&[u8]>,
    is_main: bool,
    cert: &CertificateIdentity,
) -> Result<()> {
    selfsign::sign_binary_in_place(
        binary_path, bundle_id, team_id,
        entitlements_xml, info_plist, None, cert,
    )?;

    let cs_dir = bundle_dir.join("_CodeSignature");
    std::fs::create_dir_all(&cs_dir)?;
    let cr_path = cs_dir.join("CodeResources");

    let mut prev_hash: Option<Vec<u8>> = None;

    for i in 1..=5 {
        let exe_name = binary_path.file_name()
            .and_then(|n| n.to_str());
        let cr_bytes = selfsign::code_resources::build(bundle_dir, is_main, exe_name)?;
        std::fs::write(&cr_path, &cr_bytes)?;

        use sha2::{Digest, Sha256};
        let cur_hash = {
            let mut h = Sha256::new();
            h.update(&cr_bytes);
            h.finalize().to_vec()
        };

        println!("[sign] CR loop {}: {} bytes", i, cr_bytes.len());

        if let Some(ref p) = prev_hash {
            if p == &cur_hash {
                println!("[sign] CR converged at loop {}", i);
                return Ok(());
            }
        }
        prev_hash = Some(cur_hash);

        selfsign::sign_binary_in_place(
            binary_path, bundle_id, team_id,
            entitlements_xml, info_plist, Some(&cr_bytes), cert,
        )?;
    }

    println!("[sign] CR not converged after 5 loops");
    Ok(())
}

pub fn sign_app(
    app: &mut Application,
    cert: &CertificateIdentity,
    profile_data: &[u8],
    ext_profiles: &[(String, Vec<u8>)],
    _special: &Option<SpecialApp>,
) -> Result<()> {
    println!("[sign] === sign_app ===");
    let bundle_dir = app.bundle.bundle_dir.clone();
    if !bundle_dir.exists() { return Err(anyhow!("no bundle")); }
    let sc_info = bundle_dir.join("SC_Info");
    if sc_info.exists() { std::fs::remove_dir_all(&sc_info).ok(); }
    let team_id = cert.machine_id.clone();

    let exts: Vec<_> = app.bundle.app_extensions().iter().cloned().collect();

    for ext in &exts {
        let ext_bundle_id = match ext.bundle_identifier() { Some(id) => id.to_string(), None => continue };
        let ext_exe_name = match ext.executable_name() { Some(n) => n.to_string(), None => continue };
        let ext_exe = ext.bundle_dir.join(&ext_exe_name);
        let ext_dir = ext.bundle_dir.clone();

        println!("[sign] Ext: {}", ext_bundle_id);
        let ext_profile = ext_profiles.iter().find(|(id, _)| id == &ext_bundle_id)
            .map(|(_, p)| p.as_slice())
            .ok_or_else(|| anyhow!("Ext {} missing profile", ext_bundle_id))?;
        std::fs::write(ext_dir.join("embedded.mobileprovision"), ext_profile)?;
        let ext_ent = extract_entitlements_xml(ext_profile)?;
        let ext_info = std::fs::read(ext_dir.join("Info.plist")).ok();

        sign_bundle_with_cr(&ext_dir, &ext_exe, &ext_bundle_id, &team_id,
            &ext_ent, ext_info.as_deref(), false, cert)?;
        println!("[sign] Ext OK: {}", ext_bundle_id);
    }

    let main_bundle_id = app.bundle.bundle_identifier().ok_or_else(|| anyhow!("no bundleid"))?.to_string();
    let main_exe_name = app.bundle.executable_name().ok_or_else(|| anyhow!("no exe"))?.to_string();
    let main_exe = bundle_dir.join(&main_exe_name);
    println!("[sign] Main: {}", main_bundle_id);

    let main_info = std::fs::read(bundle_dir.join("Info.plist"))?;
    std::fs::write(bundle_dir.join("embedded.mobileprovision"), profile_data)?;
    let main_ent = extract_entitlements_xml(profile_data)?;

    sign_bundle_with_cr(&bundle_dir, &main_exe, &main_bundle_id, &team_id,
        &main_ent, Some(&main_info), true, cert)?;
    println!("[sign] Main OK");
    println!("[sign] DONE");
    Ok(())
}

fn extract_entitlements_xml(profile_data: &[u8]) -> Result<Vec<u8>> {
    use plist::Value;
    let start = find_sub(profile_data, b"<plist");
    let end = rfind_sub(profile_data, b"</plist>");
    let (s, e) = match (start, end) {
        (Some(s), Some(e)) => (s, e + 8),
        _ => return Err(anyhow!("no plist")),
    };
    let plist: Value = plist::from_bytes(&profile_data[s..e])?;
    let ent = plist.as_dictionary().ok_or_else(|| anyhow!("not dict"))?
        .get("Entitlements").and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("no ent"))?;
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(ent.clone()))?;
    Ok(buf)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn rfind_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}
