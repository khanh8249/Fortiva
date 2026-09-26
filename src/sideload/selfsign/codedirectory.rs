//! CodeDirectory builder.
//!
//! Reference: isideload/sideload/macho.d CodeDirectoryBlob
//!            Apple TN3126
//!
//! Structure (version 0x20400, 88-byte header):
//!   [0..4]    magic = 0xfade0c02
//!   [4..8]    length
//!   [8..12]   version = 0x20400
//!   [12..16]  flags = 0
//!   [16..20]  hashOffset
//!   [20..24]  identOffset
//!   [24..28]  nSpecialSlots
//!   [28..32]  nCodeSlots
//!   [32..36]  codeLimit
//!   [36]      hashSize
//!   [37]      hashType
//!   [38]      platform
//!   [39]      pageSize
//!   [40..44]  spare2 = 0
//!   [44..48]  scatterOffset = 0
//!   [48..52]  teamOffset
//!   [52..56]  spare3 = 0
//!   [56..64]  codeLimit64 = 0
//!   [64..72]  execSegBase
//!   [72..80]  execSegLimit
//!   [80..88]  execSegFlags
//!   Body: bundle_id + \0 + team_id + \0 + special_slots + code_slots

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

use super::macho::MachO;

pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub const CODEDIRECTORY_VERSION: u32 = 0x20400;
pub const CD_PAGE_SIZE_LOG2: u8 = 12;  // 4KB code pages
pub const CD_PAGE_SIZE: usize = 1 << CD_PAGE_SIZE_LOG2;

pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_SHA256_LEN: usize = 32;

// Exec seg flags
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
pub const CS_EXECSEG_ALLOW_UNSIGNED: u64 = 0x10;
pub const CS_EXECSEG_DEBUGGER: u64 = 0x20;
pub const CS_EXECSEG_JIT: u64 = 0x40;
pub const CS_EXECSEG_SKIP_LV: u64 = 0x80;
pub const CS_EXECSEG_CAN_LOAD_CDHASH: u64 = 0x100;
pub const CS_EXECSEG_CAN_EXEC_CDHASH: u64 = 0x200;

/// Build CodeDirectory (SHA-256 only).
pub fn build(
    macho: &MachO,
    bundle_id: &str,
    team_id: &str,
    requirements: &[u8],
    entitlements: &[u8],
    der_entitlements: Option<&[u8]>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let hash_size = CS_SHA256_LEN;
    let hash_type = CS_HASHTYPE_SHA256;
    let is_exec = macho.is_executable();

    let code_limit = macho.code_limit();
    if code_limit == 0 {
        bail!("code_limit = 0");
    }

    // === Special slots ===
    // Order stored -N to -1 (slot -1 ở cuối):
    //   -7 (exec only): DER entitlements
    //   -6: empty
    //   -5: XML entitlements
    //   -4: empty
    //   -3: CodeResources
    //   -2: Requirements
    //   -1: Info.plist
    let empty_hash = vec![0u8; hash_size];
    let mut special_slots: Vec<Vec<u8>> = Vec::new();

    if is_exec {
        let der_hash = der_entitlements
            .map(sha256)
            .ok_or_else(|| anyhow!("Executable cần DER entitlements"))?;
        special_slots.push(der_hash);            // -7
        special_slots.push(empty_hash.clone());  // -6
    } else {
        special_slots.push(empty_hash.clone());  // -7
        special_slots.push(empty_hash.clone());  // -6
    }
    special_slots.push(sha256(entitlements));    // -5
    special_slots.push(empty_hash.clone());      // -4
    special_slots.push(
        code_resources
            .map(sha256)
            .unwrap_or_else(|| empty_hash.clone()),
    );                                            // -3
    special_slots.push(sha256(requirements));     // -2
    special_slots.push(
        info_plist
            .map(sha256)
            .unwrap_or_else(|| empty_hash.clone()),
    );                                            // -1

    // === Code slots (page hashes) ===
    let code_data = &macho.data[0..code_limit];
    let mut code_slots: Vec<Vec<u8>> = Vec::new();
    for chunk in code_data.chunks(CD_PAGE_SIZE) {
        code_slots.push(sha256(chunk));
    }

    // === Body ===
    let mut body: Vec<u8> = Vec::new();

    // bundle_id + \0
    let bundle_offset_in_body = body.len();
    body.extend_from_slice(bundle_id.as_bytes());
    body.push(0);

    // team_id + \0
    let team_offset_in_body = body.len();
    body.extend_from_slice(team_id.as_bytes());
    body.push(0);

    // special slots (concatenated)
    let hash_offset_in_body = body.len();
    for slot in &special_slots {
        if slot.len() != hash_size {
            bail!("special slot size mismatch");
        }
        body.extend_from_slice(slot);
    }

    // code slots
    for slot in &code_slots {
        if slot.len() != hash_size {
            bail!("code slot size mismatch");
        }
        body.extend_from_slice(slot);
    }

    // === Offsets ===
    let header_size: u32 = 88;
    let ident_offset: u32 = header_size + bundle_offset_in_body as u32;
    let team_offset: u32 = header_size + team_offset_in_body as u32;
    let hash_offset: u32 = header_size + hash_offset_in_body as u32;
    let total_len: u32 = header_size + body.len() as u32;

    // === Exec flags ===
    let exec_flags = compute_exec_flags(entitlements, is_exec);
    let exec_seg_base = macho.text_offset.unwrap_or(0) as u64;
    let exec_seg_limit = exec_seg_base + macho.text_size;

    // === Blob ===
    let mut blob: Vec<u8> = Vec::with_capacity(total_len as usize);

    blob.extend_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());   // [0..4]
    blob.extend_from_slice(&total_len.to_be_bytes());               // [4..8]
    blob.extend_from_slice(&CODEDIRECTORY_VERSION.to_be_bytes());   // [8..12]
    blob.extend_from_slice(&0u32.to_be_bytes());                    // [12..16] flags
    blob.extend_from_slice(&hash_offset.to_be_bytes());             // [16..20]
    blob.extend_from_slice(&ident_offset.to_be_bytes());            // [20..24]
    blob.extend_from_slice(&(special_slots.len() as u32).to_be_bytes()); // [24..28]
    blob.extend_from_slice(&(code_slots.len() as u32).to_be_bytes());    // [28..32]
    blob.extend_from_slice(&(code_limit as u32).to_be_bytes());          // [32..36]
    blob.push(hash_size as u8);                                     // [36]
    blob.push(hash_type);                                           // [37]
    blob.push(0);                                                   // [38] platform
    blob.push(CD_PAGE_SIZE_LOG2);                                   // [39] pageSize
    blob.extend_from_slice(&0u32.to_be_bytes());                    // [40..44]
    blob.extend_from_slice(&0u32.to_be_bytes());                    // [44..48]
    blob.extend_from_slice(&team_offset.to_be_bytes());             // [48..52]
    blob.extend_from_slice(&0u32.to_be_bytes());                    // [52..56]
    blob.extend_from_slice(&0u64.to_be_bytes());                    // [56..64]
    blob.extend_from_slice(&exec_seg_base.to_be_bytes());           // [64..72]
    blob.extend_from_slice(&exec_seg_limit.to_be_bytes());          // [72..80]
    blob.extend_from_slice(&exec_flags.to_be_bytes());              // [80..88]

    if blob.len() != header_size as usize {
        bail!("Header size mismatch: {} != {}", blob.len(), header_size);
    }

    blob.extend_from_slice(&body);

    if blob.len() != total_len as usize {
        bail!("Total length mismatch: {} != {}", blob.len(), total_len);
    }

    Ok(blob)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn compute_exec_flags(entitlements_xml: &[u8], is_exec: bool) -> u64 {
    let mut flags: u64 = 0;
    if is_exec {
        flags |= CS_EXECSEG_MAIN_BINARY;
    }

    if let Ok(plist) = plist::from_bytes::<plist::Value>(entitlements_xml) {
        if let Some(dict) = plist.as_dictionary() {
            if get_bool(dict, "get-task-allow") {
                flags |= CS_EXECSEG_ALLOW_UNSIGNED;
            }
            if get_bool(dict, "run-unsigned-code") {
                flags |= CS_EXECSEG_ALLOW_UNSIGNED;
            }
            if get_bool(dict, "com.apple.private.cs.debugger") {
                flags |= CS_EXECSEG_DEBUGGER;
            }
            if get_bool(dict, "dynamic-codesigning") {
                flags |= CS_EXECSEG_JIT;
            }
            if get_bool(dict, "com.apple.private.skip-library-validation") {
                flags |= CS_EXECSEG_SKIP_LV;
            }
            if get_bool(dict, "com.apple.private.amfi.can-load-cdhash") {
                flags |= CS_EXECSEG_CAN_LOAD_CDHASH;
            }
            if get_bool(dict, "com.apple.private.amfi.can-execute-cdhash") {
                flags |= CS_EXECSEG_CAN_EXEC_CDHASH;
            }
        }
    }

    flags
}

fn get_bool(dict: &plist::Dictionary, key: &str) -> bool {
    dict.get(key).and_then(|v| v.as_boolean()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_len() {
        let h = sha256(b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_exec_flags_main() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>"#;
        let flags = compute_exec_flags(xml, true);
        assert_eq!(flags & CS_EXECSEG_MAIN_BINARY, CS_EXECSEG_MAIN_BINARY);
    }

    #[test]
    fn test_exec_flags_get_task_allow() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>"#;
        let flags = compute_exec_flags(xml, true);
        assert_ne!(flags & CS_EXECSEG_ALLOW_UNSIGNED, 0);
    }
}
