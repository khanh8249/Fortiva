// src/auth/crypto/cookie.rs
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use base64::{Engine as _, engine::general_purpose};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use anyhow::{anyhow, Result};

use crate::constants::cookie_path;

fn derive_cookie_key(password: &str) -> [u8; 32] {
    const SALT: &[u8] = b"Fortiva-Cookie-Salt-v1";
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), SALT, 100_000, &mut key);
    key
}

pub fn save_cookies_encrypted(cookies_json: &str, password: &str) -> Result<()> {
    let key = derive_cookie_key(password);
    let aad = b"Fortiva-Cookies-v1";

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct_tag = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload { msg: cookies_json.as_bytes(), aad },
        )
        .map_err(|e| anyhow!("Cookie encrypt: {}", e))?;

    let mut blob = Vec::with_capacity(12 + ct_tag.len());
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ct_tag);

    let b64 = general_purpose::STANDARD.encode(&blob);

    let path = cookie_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, b64)?;
    Ok(())
}

pub fn load_cookies_encrypted(password: &str) -> Result<Option<String>> {
    let path = cookie_path();
    if !path.exists() {
        return Ok(None);
    }

    let b64 = std::fs::read_to_string(&path)?;
    let blob = general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("Cookie b64: {}", e))?;

    if blob.len() < 28 {
        return Ok(None);
    }

    let iv = &blob[..12];
    let ct_tag = &blob[12..];
    let aad = b"Fortiva-Cookies-v1";

    let key = derive_cookie_key(password);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let plaintext = cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct_tag, aad })
        .map_err(|e| anyhow!("Cookie decrypt: {}", e))?;

    Ok(Some(String::from_utf8(plaintext)?))
}