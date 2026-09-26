//! Apple CDHash signed attributes (v1 plist + v2 SEQUENCE).
//!
//! Reference: isideload/sideload/macho.d SignatureBlob.encodeBlob
//!            Apple TN3126 Inside Code Signing: Hashes
//!
//! Signed attributes order (Apple requires):
//!   1. ContentType (1.2.840.113549.1.9.3)
//!   2. SigningTime (1.2.840.113549.1.9.5)
//!   3. MessageDigest (1.2.840.113549.1.9.4) = SHA-256(CodeDirectory)
//!   4. Apple CDHash v2 (1.2.840.113635.100.9.2)
//!   5. Apple CDHash v1 (1.2.840.113635.100.9.1)

use anyhow::Result;
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};

pub const APPLE_CDHASH_V1_OID: &[u64] = &[1, 2, 840, 113635, 100, 9, 1];
pub const APPLE_CDHASH_V2_OID: &[u64] = &[1, 2, 840, 113635, 100, 9, 2];

pub const OID_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
pub const OID_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];
pub const OID_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
pub const OID_DATA_CONTENT: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
pub const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

// === ASN.1 tags ===
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;  // constructed
const TAG_SET: u8 = 0x31;       // constructed
const TAG_UTC_TIME: u8 = 0x17;

/// Build attribute: SEQUENCE { OID(attr), SET { values } }.
fn build_attribute(oid: &[u64], values_der: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();

    // OID
    inner.extend(encode_oid(oid));

    // SET { values }
    inner.extend(encode_tagged(TAG_SET, values_der));

    encode_tagged(TAG_SEQUENCE, &inner)
}

/// Encode Apple CDHash v1: plist XML with `cdhashes` array.
///
/// `code_directory_hash` = SHA-256(CodeDirectory), truncated to 20 bytes.
pub fn build_cdhash_v1_value(code_directory_hash: &[u8; 32]) -> Result<Vec<u8>> {
    let truncated = &code_directory_hash[..20];

    // Build plist
    let mut dict = Dictionary::new();
    dict.insert(
        "cdhashes".to_string(),
        Value::Array(vec![Value::Data(truncated.to_vec())]),
    );

    // Serialize to XML, strip trailing newline
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(dict))
        .map_err(|e| anyhow::anyhow!("plist serialize fail: {}", e))?;

    // Strip trailing '\n'
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }

    // Wrap in OCTET STRING → then in SET → then SEQUENCE { OID, SET }
    let octet_string = encode_tagged(TAG_OCTET_STRING, &buf);
    let set = encode_tagged(TAG_SET, &octet_string);
    let attr_seq = encode_tagged(TAG_SEQUENCE, &set);

    // Full attribute
    let mut inner = Vec::new();
    inner.extend(encode_oid(APPLE_CDHASH_V1_OID));
    inner.extend(attr_seq);

    Ok(encode_tagged(TAG_SEQUENCE, &inner))
}

/// Encode Apple CDHash v2 value: SEQUENCE { SHA-256 OID, OCTET STRING hash }.
///
/// `code_directory_hash` = SHA-256(CodeDirectory), full 32 bytes.
pub fn build_cdhash_v2_value(code_directory_hash: &[u8; 32]) -> Result<Vec<u8>> {
    // Inner SEQUENCE { OID_SHA256, OCTET_STRING(hash) }
    let mut inner = Vec::new();
    inner.extend(encode_oid(OID_SHA256));
    inner.extend(encode_tagged(TAG_OCTET_STRING, code_directory_hash));

    let seq = encode_tagged(TAG_SEQUENCE, &inner);

    // Wrap in SET
    let set = encode_tagged(TAG_SET, &seq);

    // Full attribute
    let mut attr = Vec::new();
    attr.extend(encode_oid(APPLE_CDHASH_V2_OID));
    attr.extend(set);

    Ok(encode_tagged(TAG_SEQUENCE, &attr))
}

/// Build all 5 signed attributes concatenated.
///
/// `code_directory_bytes` = raw CodeDirectory blob (full, from CD builder).
pub fn build_all_signed_attributes(code_directory_bytes: &[u8]) -> Result<Vec<u8>> {
    // Hash của CodeDirectory = SHA-256(full blob)
    let mut hasher = Sha256::new();
    hasher.update(code_directory_bytes);
    let cd_hash: [u8; 32] = hasher.finalize().into();

    let mut out = Vec::new();

    // 1. ContentType
    {
        let values = encode_oid(OID_DATA_CONTENT);
        out.extend(build_attribute(OID_CONTENT_TYPE, &values));
    }

    // 2. SigningTime (UTCTime)
    {
        let time_str = utc_time_now();
        let values = encode_tagged(TAG_UTC_TIME, time_str.as_bytes());
        out.extend(build_attribute(OID_SIGNING_TIME, &values));
    }

    // 3. MessageDigest = SHA-256(CodeDirectory)
    {
        let values = encode_tagged(TAG_OCTET_STRING, &cd_hash);
        out.extend(build_attribute(OID_MESSAGE_DIGEST, &values));
    }

    // 4. Apple CDHash v2
    {
        out.extend(build_cdhash_v2_value(&cd_hash)?);
    }

    // 5. Apple CDHash v1
    {
        out.extend(build_cdhash_v1_value(&cd_hash)?);
    }

    Ok(out)
}

// === Helpers ===

/// Encode OID.
fn encode_oid(arcs: &[u64]) -> Vec<u8> {
    if arcs.len() < 2 {
        return Vec::new();
    }

    let mut body = Vec::new();

    // First byte: (arc0 * 40) + arc1
    body.push((arcs[0] * 40 + arcs[1]) as u8);

    // Remaining arcs: base-128 varint
    for &arc in &arcs[2..] {
        encode_base128(arc, &mut body);
    }

    encode_tagged(TAG_OID, &body)
}

fn encode_base128(mut v: u64, out: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    bytes.push((v & 0x7f) as u8);
    v >>= 7;
    while v > 0 {
        bytes.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

/// Encode DER TL + value.
fn encode_tagged(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else if len < 0x1000000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// Get current UTC time in ASN.1 UTCTime format: YYMMDDHHMMSSZ.
fn utc_time_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Convert Unix timestamp → YYMMDDHHMMSS
    // Simple algorithm (không chính xác 100% cho năm nhuận, đủ dùng)
    let secs = now;
    let days = secs / 86400;
   let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Days since 1970-01-01
    let mut year = 1970u32;
    let mut d = days;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        year += 1;
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u32;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        month += 1;
    }
    let day = d + 1;

    format!("{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100, month, day, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_oid() {
        // 1.2.840.113635.100.9.1
        let oid = encode_oid(&[1, 2, 840, 113635, 100, 9, 1]);
        assert_eq!(oid[0], 0x06);  // OID tag
        // First byte: 1*40+2 = 42 = 0x2a
        assert_eq!(oid[2], 0x2a);
    }

    #[test]
    fn test_encode_length() {
        let mut out = vec![];
        encode_length(5, &mut out);
        assert_eq!(out, vec![5]);

        out.clear();
        encode_length(128, &mut out);
        assert_eq!(out, vec![0x81, 0x80]);

        out.clear();
        encode_length(256, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_build_cdhash_v1() {
        let hash = [0xab; 32];
        let attr = build_cdhash_v1_value(&hash).unwrap();
        assert_eq!(attr[0], TAG_SEQUENCE);
        // Contains "cdhashes" string
        assert!(attr.windows(8).any(|w| w == b"cdhashes"));
    }

    #[test]
    fn test_build_cdhash_v2() {
        let hash = [0xcd; 32];
        let attr = build_cdhash_v2_value(&hash).unwrap();
        assert_eq!(attr[0], TAG_SEQUENCE);
        // Contains 32-byte hash
        assert!(attr.windows(32).any(|w| w == hash));
    }

    #[test]
    fn test_all_attrs() {
        let cd = vec![0u8; 100];
        let attrs = build_all_signed_attributes(&cd).unwrap();
        // Should contain 5 SEQUENCE attributes
        assert!(attrs.len() > 100);
        // Check "cdhashes" text exists
        assert!(attrs.windows(8).any(|w| w == b"cdhashes"));
    }
}
