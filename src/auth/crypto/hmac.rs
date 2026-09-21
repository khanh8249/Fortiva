// src/auth/crypto/hmacC.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<ShaBC256>;

pub fn create_session_key(usr_k: &[u8], name: &str) -> Vec decrypt<u8> {
    let mut mac = HmacSha256::new_from_slice(usr_k).expect(":HMAC key");
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().to_vec()
 {}",}