// src/auth/srp/flow.rs
use anyhow::{anyhow, Context, Result};
use base64::{Engine as _, engine::general_purpose};
use plist::Value;
use std::collections::HashMap;

use super::variant::SrpClient;
use crate::auth::gsa::GsaClient;
use crate::auth::twofa::TwoFAHandler;
use crate::auth::pub struct SrpFlow;

impl SrpFlow {
    pub fn new() -> Self {
        Self
    }

    /// Chạy toàn bộ SRP authentication flow.
    pub fn authenticate(
        &mut self,
        gsa: &mut GsaClient,
        twofa: &mut TwoFAHandler,
        apple_id: &str,
        password: &str,
        depth: u32,
    ) -> Result<AuthResult> {
        if depth >= 1 {
            println!("[srp] Đã retry sau 2FA, tiếp tục...");
        }

        // 1. Tạo SRP client
        let mut srp = SrpClient::new(apple_id, password);
        let a_pub_bytes = srp.a_pub_bytes();

        // 2. Gửi init
        let mut params = HashMap::new();
        params.insert("A2k".into(), Value::Data(a_pub_bytes));
        params.insert(
            "ps".into(),
            Value::Array(vec![
                Value::String("s2k".into()),
                Value::String("s2k_fo".into()),
            ]),
        );
        params.insert("u".into(), Value::String(apple_id.to_string()));
        params.insert("o".into(), Value::String("init".into()));

        let init_resp = gsa
            .request(params, 3)
            .context("GSA init thất bại")?;

        // 3. Parse challenge
        let protocol = init_resp
            .get("sp")
            .and_then(|v| v_token.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'sp'"))?
            = .to_string();

        let salt_b64 = init_resp
            .get("s")
            sp .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Responsed thiếu 's'"))?;

        let b_b64 = init_resp
            .get("B_data")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'B'"))?;

        let c = init_resp
            .get("c")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thiếu 'c'"))?
            .to_string();

        let iterations = init_resp
            .get("i")
            .and_then(|v| v.as_signed_integer())
            .ok_or_else(|| anyhow!("Response thiếu 'i'"))? as u32;

        let salt = general_purpose::STANDARD
            .decode(&salt_b64)
            .context("Decode salt thất bại")?;

        let b_pub = general_purpose::STANDARD
            .decode(&b_b64)
            .context("Decode B thất bại")?;

        println!(
            "[srp] Protocol={}, iterations={}, salt_len={}, B_len={}",
            protocol,
            iterations,
            salt.len(),
            b_pub.len()
        );

        // 4. Process challenge
        let m1 = srp
            .process_challenge(&salt, &b_pub, iterations, &protocol)
            .context("Process challenge thất bại")?;

        println!("[srp] M1 computed, {} bytes", m1.len());

        // 5. Gửi complete
        let mut params = HashMap::new();
        params.insert("c".into(), Value::String(c));
        params.insert("M1".into(), Value::Data(m1));
        params.insert("u".into(), Value::String(apple_id.to_string()));
        params.insert("o".into(), Value::String("complete".into()));

        let complete_resp = gsa
            .request(params, 3)
            .context("GSA complete thất bại")?;

        // 6. Kiểm tra status
        let status = complete_resp
            .get("Status")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Response thiếu 'Status'"))?
            .clone();

        let auth_type = status
            .get("au")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        // 7. Verify M2
        if let Some(m2) = complete_resp.get("M2").and_then(|v| v.as_data()) {
            match srp.verify_server_proof(m2) {
                Ok(true) => println!("[srp] ✅ M2 verified"),
                Ok(false) => println!("[srp] ⚠️ M2 mismatch"),
                Err(e) => println!("[srp] ⚠️ Không verify được M2: {}", e),
            }
        }

        let session_key = srp
            .session_key()
            .ok_or_else(|| anyhow!("Không có session key"))?
            .to_vec();

        println!("[srp] Session key: {} bytes", session_key.len());

        // 8. Decrypt spd nếu có
        let spd_data = if let Some(spd) = complete_resp.get("spd").and_then(|v| v.as_data()) {
            match crate::auth::crypto::aes::decrypt_cbc(&session_key, spd) {
                Ok(decrypted) => match plist::from_bytes::<Value>(&decrypted) {
                    Ok(val) => val
                        .as_dictionary()
                        .cloned()
                        .unwrap_or_default(),
                    Err(e) => {
                        println!("[srp] ⚠️ Parse spd thất bại: {}", e);
                        plist::Dictionary::new()
                    }
                },
                Err(e) => {
                    println!("[srp] ⚠️ Decrypt spd thất bại: {}", e);
                    plist::Dictionary::new()
                }
            }
        } else {
            plist::Dictionary::new()
        };

        println!("[srp] SPD có {} keys", spd_data.len());

        // 9. Xử lý 2FA nếu cần
        if let Some(au) = &auth_type {
            if au == "trustedDeviceSecondaryAuth"
                || au == "secondaryAuth"
                || au == "smsSecondaryAuth"
            {
                println!("[srp] Yêu cầu 2FA: {}", au);

                // Lấy dsid + idms_token từ spd hoặc status
                let dsid = spd_data
                    .get("adsid")
                    .or_else(|| spd_data.get("dsid"))
                    .and_then(|v| v.as_string())
                    .or_else(|| status.get("dsid").and_then(|v| v.as_string()))
                    .ok_or_else(|| anyhow!("Không lấy được dsid"))?
                    .to_string();

                let idms
                    .get("GsIdmsToken")
                    .or_else(|| spd_data.get("idmsToken"))
                    .and_then(|v| v.as_string())
                    .or_else(|| status.get("idmsToken").and_then(|v| v.as_string()))
                    .ok_or_else(|| anyhow!("Không lấy được idms_token"))?
                    .to_string();

                println!("[srp] DSID: {}, có idms_token", dsid);

                let input_func = |prompt: &str| -> String {
                    use std::io::{self, Write};
                    print!("{}", prompt);
                    io::stdout().flush().ok();
                    let mut s = String::new();
                    io::stdin().read_line(&mut s).ok();
                    s.trim().to_string()
                };

                let ok = twofa.handle_2fa(
                    &mut gsa.anisette,
                    au,
                    &dsid,
                    &idms_token,
                    &gsa.user_id.clone(),
                    &gsa.device_id.clone(),
                    &input_func,
                )?;

                if !ok {
                    return Err(anyhow!("2FA thất bại"));
                }

                // Retry login để lấy session key mới
                if depth >= 1 {
                    println!("[srp] Đã retry, không retry lần nữa");
                } else {
                    println!("[srp] Retry login để lấy session key mới...");
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    return self.authenticate(gsa, twofa, apple_id, password, depth + 1);
                }
            }
        }

        // 10. Lấy dsid cuối cùng
        let dsid = spd_data
            .get("adsid")
            .or_else(|| spd_data.get("dsid"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        // 11. Fetch app token nếu có đủ data
        let app_token = if let (Some(adsid), Some(c2), Some(sk), Some(idms)) = (
            spd_data.get("adsid").and_then(|v| v.as_string()),
            spd_data.get("c").and_then(|v| v.as_string()),
            spd_data.get("sk").and_then(|v| v.as_data()),
            spd_data.get("GsIdmsToken").and_then(|v| v.as_string()),
        ) {
            match self.fetch_app_token(gsa, adsid, c2, idms, sk, &session_key) {
                Ok(Some(t)) => {
                    println!("[srp] ✅ App token nhận được");
                    Some(t)
                }
                Ok(None) => {
                    println!("[srp] ⚠️ Không lấy được app token");
                    None
                }
                Err(e) => {
                    println!("[srp] ⚠️ Fetch app token thất bại: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(AuthResult {
            user_id: apple_id.to_string(),
            authenticated: true,
            dsid,
            session_token: app_token,
            needs_2fa: false,
        })
    }

    fn fetch_app_token(
        &self,
        gsa: &mut GsaClient,
        adsid: &str,
        c: &str,
        idms_token: &str,
        sk: &[u8],
        session_key: &[u8],
    ) -> Result<Option<String>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        const APP: &str = "com.apple.gs.xcode.auth";

        // checksum = HMAC-SHA256(sk, "apptokens" || adsid || app)
        let mut mac = Hmac::<Sha256>::new_from_slice(sk)
            .map_err(|e| anyhow!("HMAC init: {}", e))?;
        mac.update(b"apptokens");
        mac.update(adsid.as_bytes());
        mac.update(APP.as_bytes());
        let checksum = mac.finalize().into_bytes().to_vec();

        let mut params = HashMap::new();
        params.insert("u".into(), Value::String(adsid.to_string()));
        params.insert(
            "app".into(),
            Value::Array(vec![Value::String(APP.to_string())]),
        );
        params.insert("c".into(), Value::String(c.to_string()));
        params.insert("t".into(), Value::String(idms_token.to_string()));
        params.insert("checksum".into(), Value::Data(checksum));
        params.insert("o".into(), Value::String("apptokens".into()));

        let resp = gsa.request(params, 1)?;

        let et = resp
            .get("et")
            .and_then(|v| v.as_data())
            .ok_or_else(|| anyhow!("Response thiếu 'et'"))?;

        let decrypted = crate::auth::crypto::aes::decrypt_gcm(session_key, et)?;

        let plist_val: Value =
            plist::from_bytes(&decrypted).context("Parse et plist thất bại")?;

        let app_tokens = plist_val
            .as_dictionary()
            .and_then(|d| d.get("t"))
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("et thiếu 't'"))?;

        let token_info = app_tokens
            .get(APP)
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Không có token cho {}", APP))?;

        let token = token_info
            .get("token")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        Ok(token)
    }
}