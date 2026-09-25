//! Entitlements blobs (XML + DER).
//!
//! Reference: isideload/sideload/macho.d EntitlementsBlob + DerEntitlementsBlob

use anyhow::{anyhow, Context, Result};
use plist::Value;

pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;

/// Build XML entitlements blob (magic + length + XML bytes).
pub fn build_xml(xml: &[u8]) -> Result<Vec<u8>> {
    if xml.is_empty() {
        return Err(anyhow!("entitlements XML rỗng"));
    }
    let total_len = 8u32 + xml.len() as u32;
    let mut blob = Vec::with_capacity(total_len as usize);
    blob.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
    blob.extend_from_slice(&total_len.to_be_bytes());
    blob.extend_from_slice(xml);
    Ok(blob)
}

/// Build DER entitlements blob.
pub fn build_der(xml: &[u8]) -> Result<Vec<u8>> {
    let der_bytes = xml_to_der(xml).context("xml_to_der fail")?;
    let total_len = 8u32 + der_bytes.len() as u32;
    let mut blob = Vec::with_capacity(total_len as usize);
    blob.extend_from_slice(&CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes());
    blob.extend_from_slice(&total_len.to_be_bytes());
    blob.extend_from_slice(&der_bytes);
    Ok(blob)
}

fn xml_to_der(xml: &[u8]) -> Result<Vec<u8>> {
    let plist: Value = plist::from_bytes(xml)
        .context("Parse XML plist fail")?;
    let dict = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Entitlements không phải dict"))?;
    let mut inner = Vec::new();
    for (key, val) in dict {
        let mut seq_inner = Vec::new();
        seq_inner.extend(encode_utf8_string(key));
        seq_inner.extend(encode_value(val)?);
        inner.extend(encode_tagged(0x30, &seq_inner));
    }
    Ok(encode_tagged(0x31, &inner))
}

fn encode_utf8_string(s: &str) -> Vec<u8> {
    encode_tagged(0x0c, s.as_bytes())
}

fn encode_value(val: &Value) -> Result<Vec<u8>> {
    Ok(match val {
        Value::Boolean(b) => vec![0x01, 0x01, if *b { 0xFF } else { 0x00 }],
        Value::Integer(i) => {
            let v = i.as_signed().unwrap_or(0);
            encode_integer(v)
        }
        Value::String(s) => encode_utf8_string(s),
        Value::Array(arr) => {
            let mut inner = Vec::new();
            for item in arr {
                inner.extend(encode_value(item)?);
            }
            encode_tagged(0x30, &inner)
        }
        Value::Dictionary(d) => {
            let mut inner = Vec::new();
            for (k, v) in d {
                let mut pair = Vec::new();
                pair.extend(encode_utf8_string(k));
                pair.extend(encode_value(v)?);
                inner.extend(encode_tagged(0x30, &pair));
            }
            encode_tagged(0x31, &inner)
        }
        Value::Data(d) => encode_tagged(0x04, d),
        _ => return Err(anyhow!("Unsupported entitlements type")),
    })
}

fn encode_integer(v: i64) -> Vec<u8> {
    let bytes: Vec<u8> = if v == 0 {
        vec![0x00]
    } else if v > 0 {
        let mut buf = v.to_be_bytes().to_vec();
        while buf.len() > 1 && buf[0] == 0x00 && buf[1] < 0x80 {
            buf.remove(0);
        }
        if buf[0] & 0x80 != 0 {
            buf.insert(0, 0x00);
        }
        buf
    } else {
        let mut buf = v.to_be_bytes().to_vec();
        while buf.len() > 1 && buf[0] == 0xFF && buf[1] >= 0x80 {
            buf.remove(0);
        }
        buf
    };
    encode_tagged(0x02, &bytes)
}

fn encode_tagged(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else if len < 0x1000000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_blob() {
        let xml = b"<plist></plist>";
        let blob = build_xml(xml).unwrap();
        assert_eq!(&blob[0..4], &[0xfa, 0xde, 0x71, 0x71]);
    }

    #[test]
    fn test_integer_encode() {
        assert_eq!(encode_integer(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(encode_integer(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_integer(0), vec![0x02, 0x01, 0x00]);
    }
}
