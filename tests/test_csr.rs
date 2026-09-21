// tests/test_csr.rs
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};

#[test]
fn test_csr_generation() {
    let rsa = Rsa::generate(2048).expect("RSA gen");
    let pkey = PKey::from_rsa(rsa).expect("PKey");

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "test-machine")
        .unwrap();
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new().unwrap();
    req_builder.set_subject_name(&name).unwrap();
    req_builder.set_pubkey(&pkey).unwrap();
    req_builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let req = req_builder.build();
    let pem = req.to_pem().unwrap();
    let pem_str = String::from_utf8(pem).unwrap();

    assert!(pem_str.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    assert!(pem_str.contains("-----END CERTIFICATE REQUEST-----"));
}