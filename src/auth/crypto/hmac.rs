// src/auth/crypto/hmac.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 từ session key + name.
pub fn create_session_key(usr_k: &[u8], name: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(usr_k).expect("HMAC key");
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
