// src/dev/certificate.rs
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder};
use plist::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

pub struct CertificateBundle {
    pub certificate_id: Option<String>,
    pub cert_content_b64: Option<String>,
    pub private_key_pem: String,
    pub csr_pem: String,
    pub machine_id: String,
}

impl DeveloperClient {
    /// Tạo cert mới hoàn chỉnh: sinh RSA key, tạo CSR, gửi Apple, lấy cert về.
    pub fn create_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        machine_name: &str,
    ) -> Result<Option<CertificateBundle>> {
        eprintln!("[DevAPI] Tạo certificate mới...");

        // 1. Sinh RSA key 2048-bit
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        // 2. Tạo CSR
        let csr_pem = build_csr(&pkey, machine_name)?;

        // 3. Gửi lên Apple
        let machine_id = Uuid::new_v4().to_string().to_uppercase();

        let mut params = HashMap::new();
        params.insert("csrContent".into(), Value::String(csr_pem.clone()));
        params.insert("machineId".into(), Value::String(machine_id.clone()));
        params.insert(
            "machineName".into(),
            Value::String(machine_name.to_string()),
        );

        let resp = self.request_plist(
            auth,
            "ios/submitDevelopmentCSR.action",
            params,
            true,
        )?;

        let cert_request = match resp.get("certRequest").and_then(|v| v.as_dictionary()) {
            Some(d) => d.clone(),
            None => {
                eprintln!("[DevAPI] Không có certRequest trong response");
                return Ok(None);
            }
        };

        // 4. Export private key PEM
        let private_key_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8()?,
        )?;

        // 5. Fetch cert content (retry)
        let cert_id = cert_request
            .get("certificateId")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        let cert_content_b64 = if let Some(id) = &cert_id {
            self.fetch_certificate_content(auth, id)?
        } else {
            None
        };

        Ok(Some(CertificateBundle {
            certificate_id: cert_id,
            cert_content_b64,
            private_key_pem,
            csr_pem,
            machine_id,
        }))
    }
}

/// Tạo CSR PEM từ RSA key.
fn build_csr(pkey: &PKey<Private>, common_name: &str) -> Result<String> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", common_name)?;
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(pkey)?;
    req_builder.sign(pkey, MessageDigest::sha256())?;

    let req: X509Req = req_builder.build();
    let pem = req.to_pem()?;

    Ok(String::from_utf8(pem)?)
}

/// Decode cert content từ Apple (base64 DER) thành DER bytes.
pub fn decode_cert_content(b64: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("Base64 decode cert: {}", e))
}