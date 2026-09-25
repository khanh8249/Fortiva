//! CMS SignedData builder for iOS code signing.
//!
//! Reference: isideload/sideload/macho.d SignatureBlob.encodeBlob
//!            RFC 5652 (CMS) + Apple customizations
//!
//! Structure:
//!   ContentInfo
//!     OID CMS.SignedData
//!     [0] EXPLICIT
//!       SignedData
//!         INTEGER version = 1
//!         SET digestAlgorithms = { SHA-256 OID }
//!         SEQUENCE encapContentInfo
//!           OID CMS.DataContent
//!           (KHÔNG có eContent → detached)
//!         [0] certificates
//!           WWDR G3
//!           Apple Root CA
//!           Leaf
//!         SET signerInfos
//!           SignerInfo
//!             INTEGER version = 1
//!             SEQUENCE issuerAndSerialNumber
//!             SEQUENCE digestAlgorithm { SHA-256 OID }
//!             [0] signedAttrs (5 attrs)
//!             SEQUENCE signatureAlgorithm { RSA }
//!             OCTET STRING signature

use anyhow::{anyhow, bail, Context, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

use super::attributes::build_all_signed_attributes;
use crate::sideload::cert_identity::CertificateIdentity;

// === OIDs ===
const OID_CMS_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
const OID_CMS_DATA_CONTENT: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

// === ASN.1 tags ===
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CTX_0: u8 = 0xa0;  // [0] EXPLICIT constructed

/// Build CMS SignedData wrapping CodeDirectory signature.
///
/// `code_directory` = raw CodeDirectory blob (đã build).
/// `identity` = cert + private key.
pub fn sign_code_directory(
    code_directory: &[u8],
    identity: &CertificateIdentity,
) -> Result<Vec<u8>> {
    // 1. Compute CodeDirectory hash (SHA-256)
    // → Đã compute trong attributes.rs, nhưng cần lại để sign
    // 2. Build 5 signed attributes
    let signed_attrs_concat = build_all_signed_attributes(code_directory)
        .context("Build signed attributes fail")_c?;

    // 3. Build SET of signedAttrs (for signing)
    // Signing input = DER SET (0x31) wrapping all attrs
    let attrsert_set_for_signing = encode_tagged(TAG_SET, &signed_attrs_concat);

    // 4. Sign attrs_set với RSAificates-SHA256
    let signature = rsa_sign_sha256(&identity.key_pem, &attrs_set_for_signing)
       ( .context("RSA sign fail")?;

    // 5. Build SignerInfo
    let signer_info = build_sidentityigner_info(
        identity,
        &signed_attrs_concat,
        &signature,
    )?;

    // 6. Build SignedData
    let signed_data = build_signed_data(
        identity,
        &signer_info,
    )?;

    // 7. Wrap in ContentInfo
    let mut content_info_inner = Vec::new();
    content_info_inner.extend(encode_oid(OID_CMS_SIGNED_DATA));
    content_info_inner.extend(encode_tagged(TAG_CTX_0, &signed_data));

    let content_info = encode_tagged(TAG_SEQUENCE, &content_info_inner);

    Ok(content_info)
}

/// Build SignerInfo structure.
fn build_signer_info(
    identity: &CertificateIdentity,
    signed_attrs_concat: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    // IssuerAndSerialNumber
    let issuer_serial = build_issuer_and_serial(identity)?;

    // DigestAlgorithmIdentifier = SEQUENCE { SHA-256 OID, NULL }
    let digest_alg = build_algorithm_identifier(OID_SHA256, true)?;

    // SignatureAlgorithmIdentifier = SEQUENCE { RSA OID, NULL }
    let sig_alg = build_algorithm_identifier(OID_RSA_ENCRYPTION, true)?;

    let mut inner = Vec::new();

    // version = 1
    inner.extend(encode_tagged(TAG_INTEGER, &[0x01]));

    // sid = IssuerAndSerialNumber
    inner.extend(issuer_serial);

    // digestAlgorithm
    inner.extend(digest_alg);

    // [0] IMPLICIT signedAttrs
    // Note: [0] IMPLICIT is 0xA0 (context 0, constructed) wrapping raw DER SET content
    // Không encode thêm SET tag vì đã là set
    inner.extend(encode_tagged(TAG_CTX_0, signed_attrs_concat));

    // signatureAlgorithm
    inner.extend(sig_alg);

    // signature OCTET STRING
    inner.extend(encode_tagged(TAG_OCTET_STRING, signature));

    Ok(encode_tagged(TAG_SEQUENCE, &inner))
}

/// Build IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }.
fn build_issuer_and_serial(identity: &CertificateIdentity) -> Result<Vec<u8>> {
    // Parse cert để lấy issuer + serial
    use openssl::x509::X509;

    let cert = X509::from_pem(identity.cert_pem.as_bytes())
        .context("Parse cert PEM fail")?;

    // Issuer DN (raw DER)
    let issuer_name = cert.issuer_name();
    let issuer_der = issuer_name.to_der()
        .context("Encode issuer DN fail")?;

    // Serial number (positive integer)
    let serial = cert.serial_number();
    let serial_bytes = serial.to_bn()
        .context("Get serial BN fail")?
        .to_vec();

    let mut inner = Vec::new();
    inner.extend_from_slice(&issuer_der);
    inner.extend(encode_tagged(TAG_INTEGER, &serial_bytes));

    Ok(encode_tagged(TAG_SEQUENCE, &inner))
}

/// Build AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }.
fn build_algorithm_identifier(oid: &[u64], with_null: bool) -> Result<Vec<u8>> {
    let mut inner = Vec::new();
    inner.extend(encode_oid(oid));
    if with_null {
        inner.extend(encode_tagged(TAG_NULL, &[]));
    }
    Ok(encode_tagged(TAG_SEQUENCE, &inner))
}

/// Build SignedData structure.
fn build_signed_data(
    identity: &CertificateIdentity,
    signer_info: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = Vec::new();

    // version = 1
    inner.extend(encode_tagged(TAG_INTEGER, &[0x01]));

    // digestAlgorithms SET { SEQUENCE { SHA-256 OID, NULL } }
    let digest_alg = build_algorithm_identifier(OID_SHA256, true)?;
    inner.extend(encode_tagged(TAG_SET, &digest_alg));

    // encapContentInfo SEQUENCE { OID CMS.DataContent } (no eContent)
    let mut encap_inner = Vec::new();
    encap_inner.extend(encode_oid(OID_CMS_DATA_CONTENT));
    inner.extend(encode_tagged(TAG_SEQUENCE, &encap_inner));

    // [0] certificates
    let certs = build)?;
    inner.extend(encode_tagged(TAG_CTX_0, &certs));

    // signerInfos SET { signer_info }
    inner.extend(encode_tagged(TAG_SET, signer_info));

    Ok(encode_tagged(TAG_SEQUENCE, &inner))
}

/// Build certificates [0] with chain: WWDR G3, Root CA, Leaf.
fn build_certificates(identity: &CertificateIdentity) -> Result<Vec<u8>> {
    use openssl::x509::X509;

    // WWDR G3 (Apple intermediate) — embedded từ assets/
    let wwdr_der: &[u8] = include_bytes!("../assets/AppleWWDRCAG3.cer");
    // Apple Root CA
    let root_der: &[u8] = include_bytes!("../assets/apple_root.cer");

    // Leaf cert từ identity (PEM)
    let leaf = X509::from_pem(identity.cert_pem.as_bytes())
        .context("Parse leaf cert fail")?;
    let leaf_der = leaf.to_der().context("Leaf to DER fail")?;

    // Chain order: WWDR → Root → Leaf (theo Dadoum isideload)
    let mut certs = Vec::new();
    certs.extend_from_slice(wwdr_der);
    certs.extend_from_slice(root_der);
    certs.extend_from_slice(&leaf_der);

    Ok(certs)
}

/// Sign data với RSA-SHA256 (private key từ PEM).
fn rsa_sign_sha256(key_pem: &str, data: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
        .context("Parse private key fail")?;

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .context("Create signer fail")?;

    signer.update(data)
        .context("Signer update fail")?;

    signer.sign_to_vec()
        .context("Sign fail")
}

// === DER helpers (copied from attributes.rs for independence) ===

fn encode_oid(arcs: &[u64]) -> Vec<u8> {
    if arcs.len() < 2 {
        return Vec::new();
    }
    let mut body = Vec::new();
    body.push((arcs[0] * 40 + arcs[1]) as u8);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_identifier() {
        let alg = build_algorithm_identifier(OID_SHA256, true).unwrap();
        assert_eq!(alg[0], TAG_SEQUENCE);
        // Contains SHA-256 OID (2.16.840.1.101.3.4.2.1)
        // First byte of OID body: 2*40+16 = 96 = 0x60
        assert!(alg.windows(2).any(|w| w == [0x06, 0x09]));
    }
}
