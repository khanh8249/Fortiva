use anyhow::{anyhow, Context, Result};

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
        return Err(anyhow!("Bundle dir missing"));
    }

    let sc_info = bundle_dir.join("SC_Info");
    if sc_info.exists() {
        std::fs::remove_dir_all(&sc_info).ok();
    }

    let team_id = cert.machine_id.clone();
    let exts: Vec<_> = app.bundle.app_extensions().iter().cloned().collect();

    for ext in &exts {
        let ext_bundle_id = match ext.bundle_identifier() {
            Some(id) => id.to_string(),
            None => continue,
        };
        let ext_exe_name = match ext.executable_name() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let ext_exe = ext.bundle_dir.join(&ext_exe_name);
        let ext_dir = ext.bundle_dir.clone();

        println!("[sign] Ext: {}", ext_bundle_id);

        let ext_profile = ext_profiles.iter()
            .find(|(id, _)| id == &ext_bundle_id)
            .map(|(_, p)| p.as_slice())
            .ok_or_else(|| anyhow!("Ext {} missing profile", ext_bundle_id))?;

        std::fs::write(ext_dir.join("embedded.mobileprovision"), ext_profile)?;
        let ext_entitlements = extract_entitlements_xml(ext_profile)?;
        let ext_info_plist = std::fs::read(ext_dir.join("Info.plist")).ok();

        let ext_cr = selfsign::code_resources::build(&ext_dir, false)?;
        println!("[sign] Ext CR: {} bytes", ext_cr.len());

        let ext_cs = ext_dir.join("_CodeSignature");
        std::fs::create_dir_all(&ext_cs)?;
        std::fs::write(ext_cs.join("CodeResources"), &ext_cr)?;

        selfsign::sign_binary_in_place(
            &ext_exe, &ext_bundle_id, &team_id,
            &ext_entitlements, ext_info_plist.as_deref(),
            Some(&ext_cr), cert,
        )?;
        println!("[sign] Ext OK: {}", ext_bundle_id);
    }

    let main_bundle_id = app.bundle.bundle_identifier()
        .ok_or_else(|| anyhow!("No CFBundleIdentifier"))?.to_string();
    let main_exe_name = app.bundle.executable_name()
        .ok_or_else(|| anyhow!("No CFBundleExecutable"))?.to_string();
    let main_exe = bundle_dir.join(&main_exe_name);

    println!("[sign] Main: {}", main_bundle_id);

    let main_info_plist = std::fs::read(bundle_dir.join("Info.plist"))?;
    std::fs::write(bundle_dir.join("embedded.mobileprovision"), profile_data)?;
    let main_entitlements = extract_entitlements_xml(profile_data)?;

    let main_cr = selfsign::code_resources::build(&bundle_dir, true)?;
    println!("[sign] Main CR: {} bytes", main_cr.len());

    let main_cs = bundle_dir.join("_CodeSignature");
    std::fs::create_dir_all(&main_cs)?;
    std::fs::write(main_cs.join("CodeResources"), &main_cr)?;

    selfsign::sign_binary_in_place(
        &main_exe, &main_bundle_id, &team_id,
        &main_entitlements, Some(&main_info_plist),
        Some(&main_cr), cert,
    )?;
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
        _ => return Err(anyhow!("No plist in profile")),
    };
    let plist: Value = plist::from_bytes(&profile_data[s..e])?;
    let ent = plist.as_dictionary()
        .ok_or_else(|| anyhow!("Profile not dict"))?
        .get("Entitlements").and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("No Entitlements"))?;
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
