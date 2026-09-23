// src/auth/srp/variant.rs
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_traits::Num;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::auth::crypto::aes::encrypt_password;

const N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);

const G_HEX: &str = "02";
const N_LEN: usize = 256;

pub struct SrpClient {
    username: String,
    password: String,
    a: BigUint,
    pub a_pub: BigUint,
    n: BigUint,
    g: BigUint,
    k: BigUint,
    salt: Option<Vec<u8>>,
    b_pub: Option<BigUint>,
    u: Option<BigUint>,
    session_key: Option<Vec<u8>>,
    m1: Option<Vec<u8>>,
}

impl SrpClient {
    pub fn new(username: &str, password: &str) -> Self {
        let n = BigUint::from_str_radix(N_HEX, 16).expect("Parse N");
        let g = BigUint::from_str_radix(G_HEX, 16).expect("Parse g");

        let n_bytes = pad_to_n(&n);
        let g_padded = pad_to_n(&g);
        let mut hasher = Sha256::new();
        hasher.update(&n_bytes);
        hasher.update(&g_padded);
        let k_bytes = hasher.finalize();
        let k = BigUint::from_bytes_be(&k_bytes);

        let mut rng = rand::thread_rng();
        let a_bytes: [u8; 32] = rng.gen();
        let a = BigUint::from_bytes_be(&a_bytes);

        let a_pub = g.modpow(&a, &n);

        Self {
            username: username.to_string(),
            password: password.to_string(),
            a,
            a_pub,
            n,
            g,
            k,
            salt: None,
            b_pub: None,
            u: None,
            session_key: None,
            m1: None,
        }
    }

    pub fn a_pub_bytes(&self) -> Vec<u8> {
        pad_to_n(&self.a_pub)
    }

    pub fn process_challenge(
        &mut self,
        salt: &[u8],
        b_pub_bytes: &[u8],
        iterations: u32,
        protocol: &str,
    ) -> Result<Vec<u8>> {
        self.salt = Some(salt.to_vec());

        let b_pub = BigUint::from_bytes_be(b_pub_bytes);
        self.b_pub = Some(b_pub.clone());

        let a_padded = pad_to_n(&self.a_pub);
        let b_padded = pad_to_n(&b_pub);
        let mut hasher = Sha256::new();
        hasher.update(&a_padded);
        hasher.update(&b_padded);
        let u_bytes = hasher.finalize();
        let u = BigUint::from_bytes_be(&u_bytes);
        self.u = Some(u.clone());

        let p = encrypt_password(&self.password, salt, iterations, protocol);

        // FIX ec=-22406: với Apple, x = P, KHÔNG hash thêm
        let x = BigUint::from_bytes_be(&p);

        let g_x = self.g.modpow(&x, &self.n);
        let k_g_x = (&self.k * &g_x) % &self.n;

        let base = if b_pub >= k_g_x {
            (&b_pub - &k_g_x) % &self.n
        } else {
            (&self.n + &b_pub - &k_g_x) % &self.n
        };

        let exp = &self.a + &u * &x;
        let s = base.modpow(&exp, &self.n);

        let s_padded = pad_to_n(&s);
        let mut hasher = Sha256::new();
        hasher.update(&s_padded);
        let k_session = hasher.finalize().to_vec();
        self.session_key = Some(k_session.clone());

        let h_n = {
            let mut h = Sha256::new();
            h.update(&pad_to_n(&self.n));
            h.finalize()
        };
        let h_g = {
            let mut h = Sha256::new();
            h.update(&pad_to_n(&self.g));
            h.finalize()
        };
        let h_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();

        let h_username = {
            let mut h = Sha256::new();
            h.update(self.username.as_bytes());
            h.finalize()
        };

        let mut hasher = Sha256::new();
        hasher.update(&h_xor);
        hasher.update(&h_username);
        hasher.update(salt);
        hasher.update(&a_padded);
        hasher.update(&b_padded);
        hasher.update(&k_session);
        let m1 = hasher.finalize().to_vec();

        self.m1 = Some(m1.clone());

        Ok(m1)
    }

    pub fn verify_server_proof(&self, m2_from_server: &[u8]) -> Result<bool> {
        let m1 = self
            .m1
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa gọi process_challenge"))?;
        let k_session = self
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa có session key"))?;

        let a_padded = pad_to_n(&self.a_pub);

        let mut hasher = Sha256::new();
        hasher.update(&a_padded);
        hasher.update(m1);
        hasher.update(k_session);
        let expected_m2 = hasher.finalize().to_vec();

        Ok(expected_m2 == m2_from_server)
    }

    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

fn pad_to_n(x: &BigUint) -> Vec<u8> {
    let bytes = x.to_bytes_be();
    if bytes.len() >= N_LEN {
        return bytes;
    }
    let mut out = vec![0u8; N_LEN - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}
