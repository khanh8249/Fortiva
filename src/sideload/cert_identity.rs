// src/sideload/cert_identity.rs
use anyhow::{anyhow, Context, Result};
use base64::{Engine as _, engine::general_purpose};
use std::path::Path;

pub struct CertificateIdentity {
    pub machine_id: String,
    pub machine_name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub serial_number: String,
}

impl CertificateIdentity {
    /// Load từ cert.pem + key.pem có sẵn.
    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("Đọc cert thất bại: {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("Đọc key thất bại: {}", key_path.display()))?;

        // Extract serial number từ cert PEM
        let serial = extract_serial_from_pem(&cert_pem)?;

        // Extract Team ID
        let machine_id = extract_team_id_from_pem(&cert_pem).unwrap_or_default();
        let machine_name = extract_cn_from_pem(&cert_pem).unwrap_or_default();

        Ok(Self {
            machine_id,
            machine_name,
            cert_pem,
            key_pem,
            serial_number: serial,
        })
    }

    pub fn serial_number(&self) -> String {
        self.serial_number.clone()
    }

    /// Tao tu CertificateBundle (da co cert + key).
    pub fn from_bundle(bundle: &crate::dev::CertificateBundle) -> Result<Self> {
        let cert_content = bundle.cert_content_b64.as_ref()
            .ok_or_else(|| anyhow!("Bundle thieu cert_content_b64"))?;

        // Apple co the tra ve 3 format: PEM, base64, hoac DER-b64
        let cert = if cert_content.contains("-----BEGIN CERTIFICATE-----") {
            openssl::x509::X509::from_pem(cert_content.as_bytes())
                .context("Parse cert PEM that bai")?
        } else {
            // Thu base64 decode -> DER
            let der = general_purpose::STANDARD
                .decode(cert_content)
                .context("Decode cert base64 that bai")?;
            openssl::x509::X509::from_der(&der)
                .context("Parse cert DER that bai")?
        };

        let cert_pem = String::from_utf8(cert.to_pem()?)
            .context("Convert cert PEM that bai")?;

        let serial = extract_serial_from_pem(&cert_pem)?;
        let machine_id = extract_team_id_from_pem(&cert_pem).unwrap_or_default();
        let machine_name = extract_cn_from_pem(&cert_pem).unwrap_or_default();

        Ok(Self {
            machine_id,
            machine_name,
            cert_pem,
            key_pem: bundle.private_key_pem.clone(),
            serial_number: serial,
        })
    }

    /// Export ra PKCS#12.
    pub fn as_p12(&self, password: &str) -> Result<Vec<u8>> {
        use openssl::pkcs12::Pkcs12;
        use openssl::pkey::PKey;
        use openssl::x509::X509;

        let cert = X509::from_pem(self.cert_pem.as_bytes())
            .context("Parse cert PEM thất bại")?;
        let pkey = PKey::private_key_from_pem(self.key_pem.as_bytes())
            .context("Parse key PEM thất bại")?;

        let pkcs12 = Pkcs12::builder()
            .name("fortiva")
            .pkey(&pkey)
            .cert(&cert)
            .build2(password)
            .context("Build PKCS#12 thất bại")?;

        Ok(pkcs12.to_der()?)
    }
}

fn extract_serial_from_pem(pem: &str) -> Result<String> {
    use openssl::x509::X509;
    let cert = X509::from_pem(pem.as_bytes())?;
    let serial = cert.serial_number().to_bn()?.to_hex_str()?;
    Ok(serial.to_string().trim_start_matches('0').to_uppercase())
}

fn extract_team_id_from_pem(pem: &str) -> Option<String> {
    use openssl::x509::X509;
    let cert = X509::from_pem(pem.as_bytes()).ok()?;
    let subject = cert.subject_name();
    let entries = subject.entries();
    for entry in entries {
        let data = entry.data().as_slice();
        let s = String::from_utf8_lossy(data).to_string();
        if s.len() == 10 && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return Some(s);
        }
    }
    None
}

fn extract_cn_from_pem(pem: &str) -> Option<String> {
    use openssl::x509::X509;
    use openssl::nid::Nid;
    let cert = X509::from_pem(pem.as_bytes()).ok()?;
    let subject = cert.subject_name();
    let entries = subject.entries_by_nid(Nid::COMMONNAME);
    let entry = entries.into_iter().next()?;
    Some(String::from_utf8_lossy(entry.data().as_slice()).to_string())
}

// ============================================================
//  CERTIFICATE CHAIN — port tu isideload
// ============================================================

pub const APPLE_ROOT: &[u8] = include_bytes!("assets/apple_root.cer");
pub const APPLE_WWDR_G3_CERTIFICATE_DER: &[u8] = include_bytes!("assets/AppleWWDRCAG3.cer");

/// Build certificate chain tu profile + cert Apple goc.
pub fn build_certificate_chain(
    profile_certs_der: &[Vec<u8>],
    my_cert_der: &[u8],
) -> Result<Vec<Vec<u8>>> {
    use der::Decode;
    use x509_cert::Certificate;

    let mut candidates: Vec<Certificate> = Vec::new();

    // 1. Parse my cert
    let my_cert = Certificate::from_der(my_cert_der)
        .map_err(|e| anyhow!("Parse my cert fail: {}", e))?;

    // 2. Parse certs tu profile
    for der in profile_certs_der {
        let cert = Certificate::from_der(der.as_ref())
            .map_err(|e| anyhow!("Parse profile cert fail: {}", e))?;
        if !candidates.contains(&cert) {
            candidates.push(cert);
        }
    }

    // 3. Them 2 cert Apple
    for (_name, cert_der) in [
        ("Apple WWDR G3", APPLE_WWDR_G3_CERTIFICATE_DER),
        ("Apple Root CA", APPLE_ROOT),
    ] {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| anyhow!("Parse Apple cert fail: {}", e))?;
        if !candidates.contains(&cert) {
            candidates.push(cert);
        }
    }

    // 4. Walk chain tu my_cert len root
    let mut chain: Vec<Certificate> = Vec::new();
    let mut issuer = my_cert.tbs_certificate.issuer.clone();

    loop {
        let cert = candidates
            .iter()
            .find(|c| c.tbs_certificate.subject == issuer)
            .ok_or_else(|| anyhow!("Missing issuer cert: {:?}", issuer))?
            .clone();

        if chain.contains(&cert) {
            return Err(anyhow!("Chain cycle detected"));
        }

        let is_root = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
        issuer = cert.tbs_certificate.issuer.clone();
        chain.push(cert);

        if is_root {
            break;
        }
    }

    // 5. Return DER bytes
    use der::Encode;
    let mut out = Vec::new();
    for cert in chain {
        let der = cert.to_der()
            .map_err(|e| anyhow!("Encode cert fail: {}", e))?;
        out.push(der);
    }
    Ok(out)
}
