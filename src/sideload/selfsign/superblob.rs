//! SuperBlob assembly.
//!
//! Reference: isideload/sideload/macho.d EmbeddedSignature
//!
//! Structure:
//!   SuperBlob header (12 bytes):
//!     [0..4]   magic = CSMAGIC_EMBEDDED_SIGNATURE (0xfade0cc0)
//!     [4..8]   length = total
//!     [8..12]  count = số blobs
//!   Index entries (count × 8 bytes):
//!     each: [slot_type(4)] [offset(4)]
//!   Blob data (concatenated, 4-byte aligned)

use anyhow::{anyhow, Result};

pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;

pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// Assemble SuperBlob.
///
/// Order: CodeDirectory (0), Requirements (2), Entitlements (5),
///        [DER Entitlements (7)], CMS (0x10000).
pub fn assemble(
    code_directory: &[u8],
    requirements: &[u8],
    entitlements: &[u8],
    der_entitlements: Option<&[u8]>,
    cms: &[u8],
) -> Result<Vec<u8>> {
    if code_directory.is_empty() {
        return Err(anyhow!("CodeDirectory rỗng"));
    }
    if requirements.is_empty() {
        return Err(anyhow!("Requirements rỗng"));
    }
    if entitlements.is_empty() {
        return Err(anyhow!("Entitlements rỗng"));
    }
    if cms.is_empty() {
        return Err(anyhow!("CMS rỗng"));
    }

    // Build blobs list (slot_type, data)
    let mut blobs: Vec<(u32, &[u8])> = vec![
        (CSSLOT_CODEDIRECTORY, code_directory),
        (CSSLOT_REQUIREMENTS, requirements),
        (CSSLOT_ENTITLEMENTS, entitlements),
    ];
    if let Some(der) = der_entitlements {
        blobs.push((CSSLOT_DER_ENTITLEMENTS, der));
    }
    blobs.push((CSSLOT_SIGNATURESLOT, cms));

    let count = blobs.len() as u32;
    let header_size = 12u32 + count * 8;

    // Compute offsets (4-byte aligned)
    let mut offset = header_size;
    let mut index_entries: Vec<(u32, u32)> = Vec::with_capacity(count as usize);
    for (slot, data) in &blobs {
        index_entries.push((*slot, offset));
        offset += data.len() as u32;
        // Pad to 4 bytes
        let rem = offset % 4;
        if rem != 0 {
            offset += 4 - rem;
        }
    }
    let total_len = offset;

    // Build output
    let mut out = Vec::with_capacity(total_len as usize);

    // Header
    out.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());

    // Index entries
    for (slot, off) in &index_entries {
        out.extend_from_slice(&slot.to_be_bytes());
        out.extend_from_slice(&off.to_be_bytes());
    }

    // Blob data with padding
    for (i, (_, data)) in blobs.iter().enumerate() {
        out.extend_from_slice(data);
        // Padding to next offset (except last)
        if i + 1 < blobs.len() {
            let next = index_entries[i + 1].1 as usize;
            while out.len() < next {
                out.push(0);
            }
        }
    }

    // Final padding
    while out.len() < total_len as usize {
        out.push(0);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_superblob() {
        let cd = vec![1u8; 100];
        let req = vec![2u8; 12];
        let ent = vec![3u8; 20];
        let cms = vec![4u8; 50];

        let sb = assemble(&cd, &req, &ent, None, &cms).unwrap();
        assert_eq!(&sb[0..4], &[0xfa, 0xde, 0x0c, 0xc0]);

        let count = u32::from_be_bytes([sb[8], sb[9], sb[10], sb[11]]);
        assert_eq!(count, 4);

        let total = u32::from_be_bytes([sb[4], sb[5], sb[6], sb[7]]);
        assert_eq!(total as usize, sb.len());
    }

    #[test]
    fn test_with_der() {
        let cd = vec![1u8; 100];
        let req = vec![2u8; 12];
        let ent = vec![3u8; 20];
        let der = vec![5u8; 30];
        let cms = vec![4u8; 50];

        let sb = assemble(&cd, &req, &ent, Some(&der), &cms).unwrap();
        let count = u32::from_be_bytes([sb[8], sb[9], sb[10], sb[11]]);
        assert_eq!(count, 5);
    }
}
