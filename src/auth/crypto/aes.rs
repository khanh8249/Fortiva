// src/auth/crypto/aes.rs
use aes::Aes256;
use aes_gcm::{aead::{Aead, KeyInit, Payload}};
use aes_gcm::aead::consts::U16;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use anyhow::{anyhow, Result};

use super::hmac::create_session_key;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256Gcm16 = aes_gcm::AesGcm<aes::Aes256, U16>;

pub fn encrypt_password(password: &str, salt: &[u8], iterations: u32, protocol: &str) -> Vec<u8> {
    let mut p = Sha256::digest(password.as_bytes()).to_vec();
    if protocol == "s2k_fo" {
        p = hex::encode(p).into_bytes();
    }

    // === DEBUG (che password) ===
    let pw_hash_prefix = &hex::encode(Sha256::digest(password.as_bytes()))[..16];
    eprintln!("[DBG-RUST] === encrypt_password ===");
    eprintln!("[DBG-RUST] password_len   = {}", password.len());
    eprintln!("[DBG-RUST] password_sha256_prefix = {}", pw_hash_prefix);
    eprintln!("[DBG-RUST] protocol       = {}", protocol);
    eprintln!("[DBG-RUST] iterations     = {}", iterations);
    eprintln!("[DBG-RUST] salt           = {}", hex::encode(salt));
    eprintln!("[DBG-RUST] p (pre-pbkdf2) = {}", hex::encode(&p));
    // === END DEBUG ===

    let mut out = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(&p, salt, iterations, &mut out);

    // === DEBUG ===
    eprintln!("[DBG-RUST] p (post-pbkdf2)= {}", hex::encode(&out));
    eprintln!("[DBG-RUST] ========================");
    // === END DEBUG ===

    out
}

pub fn decrypt_cbc(usr_k: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = create_session_key(usr_k, "extra data key:");
    let iv_full = create_session_key(usr_k, "extra data iv:");
    let iv = &iv_full[..16];

    let cipher = Aes256CbcDec::new_from_slices(&key, iv)
        .map_err(|e| anyhow!("CBC init: {}", e))?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|e| anyhow!("CBC decrypt: {}", e))
}

pub fn decrypt_gcm(sk: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 35 {
        return Err(anyhow!("Encrypted token quá ngắn"));
    }
    if &encrypted_data[..3] != b"XYZ" {
        return Err(anyhow!("Version token không đúng"));
    }

    let aad = &encrypted_data[..3];
    let iv = &encrypted_data[3..19];
    let ciphertext = &encrypted_data[19..encrypted_data.len() - 16];
    let tag = &encrypted_data[encrypted_data.len() - 16..];

    // Apple dung nonce 16 bytes (khong chuan GCM 12)
    let key = aes_gcm::Key::<Aes256Gcm16>::from_slice(sk);
    let cipher = Aes256Gcm16::new(key);
    let nonce = aes_gcm::Nonce::<U16>::from_slice(iv);

    let mut ct = ciphertext.to_vec();
    ct.extend_from_slice(tag);

    cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .map_err(|e| anyhow!("GCM decrypt: {}", e))
}
