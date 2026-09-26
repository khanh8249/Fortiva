//! Self-sign — own implementation of iOS code signing.
//!
//! Reference: Apple TN3126 + isideload (Dadoum) macho.d

pub mod macho;
pub mod codedirectory;
pub mod entitlements;
pub mod requirements;
pub mod cms;
pub mod attributes;
pub mod superblob;
pub mod code_resources;

use anyhow::Result;
use std::path::Path;

use crate::sideload::cert_identity::CertificateIdentity;

pub fn sign_binary_in_place(
    binary_path: &Path,
    bundle_id: &str,
    team_id: &str,
    entitlements_xml: &[u8],
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    identity: &CertificateIdentity,
) -> Result<()> {
    let data = std::fs::read(binary_path)?;
    let macho = macho::MachO::parse(&data)?;

    let requirements = requirements::build_empty()?;
    let entitlements = entitlements::build_xml(entitlements_xml)?;
    let der_entitlements = if macho.is_executable() {
        Some(entitlements::build_der(entitlements_xml)?)
    } else {
        None
    };

    let code_directory = codedirectory::build(
        &macho, bundle_id, team_id,
        &requirements, &entitlements, der_entitlements.as_deref(),
        info_plist, code_resources,
    )?;

    let cms = cms::sign_code_directory(&code_directory, identity)?;

    let superblob = superblob::assemble(
        &code_directory, &requirements, &entitlements,
        der_entitlements.as_deref(), &cms,
    )?;

    let signed_data = macho::inject_signature(&data, &superblob)?;
    std::fs::write(binary_path, signed_data)?;
    Ok(())
}
