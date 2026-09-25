//! Requirements blob (empty requirements set).
//!
//! Reference: isideload/sideload/macho.d RequirementsBlob

use anyhow::Result;

pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;

/// Build empty requirements blob (12 bytes):
///   [0..4]   magic = 0xfade0c01
///   [4..8]   length = 12
///   [8..12]  count = 0
pub fn build_empty() -> Result<Vec<u8>> {
    let mut blob = Vec::with_capacity(12);
    blob.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    blob.extend_from_slice(&12u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_requirements() {
        let blob = build_empty().unwrap();
        assert_eq!(blob.len(), 12);
        assert_eq!(&blob[0..4], &[0xfa, 0xde, 0x0c, 0x01]);
        assert_eq!(&blob[4..8], &[0, 0, 0, 12]);
        assert_eq!(&blob[8..12], &[0, 0, 0, 0]);
    }
}
