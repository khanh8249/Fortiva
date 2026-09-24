// src/auth/srp/flow.rs
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};

use hmac::{Hmac, Mac};
use plist::{Dictionary, Value};
use sha2::Sha256;
use std::collections::HashMap;

use super::variant::SrpClient;
use crate::auth::crypto::aes::{decrypt_cbc, decrypt_gcm};
use crate::auth::gsa::GsaClient;
use crate::auth::twofa::TwoFAHandler;
use crate::AuthResult;

const APP_XCODE_AUTH: &str = "com.apple.gs.xcode.auth";


/// Extract data field tu plist::Value.
/// Ho tro ca String (base64) va Data (raw bytes).
fn extract_data_field(value: Option<&Value>, field: &str) -> Result<Vec<u8>> {
    match value {
        Some(Value::String(s)) => {
            
            general_purpose::STANDARD
                .decode(s)
                .with_context(|| format!("Decode {} base64 that bai", field))
        }
        Some(Value::Data(d)) => Ok(d.to_vec()),
        Some(other) => Err(anyhow!(
            "Field '{}' sai type: {:?}. Expected String hoac Data",
            field,
            other
        )),
        None => Err(anyhow!("Response thieu field '{}'", field)),
    }
}

pub struct SrpFlow;

impl SrpFlow {
    pub fn new() -> Self {
        Self
    }

    pub fn authenticate(
        &mut self,
        gsa: &mut GsaClient,
        twofa: &mut TwoFAHandler,
        apple_id: &str,
        password: &str,
        depth: u32,
    ) -> Result<AuthResult> {
        if depth > 0 {
            println!("[srp] Retry sau 2FA (depth={})...", depth);
        }

        let mut srp = SrpClient::new(apple_id, password);
        let a_pub_bytes = srp.a_pub_bytes();

        let mut params: HashMap<String, Value> = HashMap::new();
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

        println!("[srp] Gui init request...");
        let init_resp = gsa.request(params, 3).context("GSA init that bai")?;

        let protocol = init_resp
            .get("sp")
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("Response thieu 'sp'"))?
            .to_string();

        let salt = extract_data_field(init_resp.get("s"), "s")?;

        let b_pub = extract_data_field(init_resp.get("B"), "B")?;


        // c co the la String hoac Data
        let c = match init_resp.get("c") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Data(d)) => {
                
                general_purpose::STANDARD.encode(d)
            }
            other => return Err(anyhow!("Field 'c' sai type: {:?}", other)),
        };

        let iterations = init_resp
            .get("i")
            .and_then(plist_integer)
            .ok_or_else(|| anyhow!("Response thieu 'i'"))? as u32;



        println!(
            "[srp] Protocol={}, iterations={}, salt_len={}, B_len={}",
            protocol,
            iterations,
            salt.len(),
            b_pub.len()
        );

        let m1 = srp
            .process_challenge(&salt, &b_pub, iterations, &protocol)
            .context("Process SRP challenge that bai")?;

        println!("[srp] M1 computed ({} bytes)", m1.len());

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("c".into(), Value::String(c));
        params.insert("M1".into(), Value::Data(m1));
        params.insert("u".into(), Value::String(apple_id.to_string()));
        params.insert("o".into(), Value::String("complete".into()));

        println!("[srp] Gui complete request...");
        let complete_resp = gsa.request(params, 3).context("GSA complete that bai")?;

        let status = complete_resp
            .get("Status")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Response thieu 'Status'"))?
            .clone();

        let auth_type = status
            .get("au")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        if let Some(m2) = complete_resp.get("M2").and_then(|v| v.as_data()) {
            match srp.verify_server_proof(m2) {
                Ok(true) => println!("[srp] M2 verified"),
                Ok(false) => println!("[srp] M2 mismatch"),
                Err(e) => println!("[srp] Khong verify duoc M2: {}", e),
            }
        }

        let session_key = srp
            .session_key()
            .ok_or_else(|| anyhow!("Khong co session key"))?
            .to_vec();

        println!("[srp] Session key OK ({} bytes)", session_key.len());

        let spd_data: Dictionary = if let Some(spd) = complete_resp.get("spd").and_then(|v| v.as_data()) {
            match decrypt_cbc(&session_key, spd) {
                Ok(decrypted) => match plist::from_bytes::<Value>(&decrypted) {
                    Ok(val) => val.as_dictionary().cloned().unwrap_or_default(),
                    Err(e) => {
                        println!("[srp] Parse spd that bai: {}", e);
                        Dictionary::new()
                    }
                },
                Err(e) => {
                    println!("[srp] Decrypt spd CBC that bai: {}", e);
                    Dictionary::new()
                }
            }
        } else {
            Dictionary::new()
        };

        println!("[srp] SPD co {} keys", spd_data.len());
        
        // DEBUG SPD keys
        eprintln!("[DBG-SPD] adsid: {}", spd_data.get("adsid").is_some());
        eprintln!("[DBG-SPD] c: {}", spd_data.get("c").is_some());
        eprintln!("[DBG-SPD] sk: {}", spd_data.get("sk").is_some());
        eprintln!("[DBG-SPD] GsIdmsToken: {}", spd_data.get("GsIdmsToken").is_some());
        eprintln!("[DBG-SPD] idmsToken: {}", spd_data.get("idmsToken").is_some());
        let all_keys: Vec<&str> = spd_data.keys().map(|k| k.as_str()).collect();
        eprintln!("[DBG-SPD] All keys ({}): {:?}", all_keys.len(), all_keys);

        if let Some(au) = &auth_type {
            if au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth" || au == "smsSecondaryAuth" {
                println!("[srp] Yeu cau 2FA: {}", au);

                // Delay 3s trước khi gửi 2FA — tránh Apple 403 vì request quá nhanh
                println!("[srp] Chờ 3s trước khi gửi 2FA request...");
                std::thread::sleep(std::time::Duration::from_secs(3));

                let dsid = extract_string(&spd_data, &["adsid", "dsid"])
                    .or_else(|| extract_string(&status, &["dsid"]))
                    .ok_or_else(|| anyhow!("Khong lay duoc dsid cho 2FA"))?;

                let idms_token = extract_string(&spd_data, &["GsIdmsToken", "idmsToken"])
                    .or_else(|| extract_string(&status, &["idmsToken"]))
                    .ok_or_else(|| anyhow!("Khong lay duoc idms_token cho 2FA"))?;

                println!("[srp] DSID: {}", dsid);

                let input_func = |prompt: &str| -> String {
                    use std::io::{self, Write};
                    print!("{}", prompt);
                    io::stdout().flush().ok();
                    let mut s = String::new();
                    io::stdin().read_line(&mut s).ok();
                    s.trim().to_string()
                };

                let twofa_ok = TwoFAHandler::handle_2fa(
                    twofa,
                    &mut gsa.anisette,
                    au,
                    &dsid,
                    &idms_token,
                    &gsa.user_id.clone(),
                    &gsa.device_id.clone(),
                    &input_func,
                )?;

                if !twofa_ok {
                    return Err(anyhow!("2FA that bai"));
                }

                if depth >= 1 {
                    println!("[srp] Da retry 2FA roi, tiep tuc (khong retry nua)");
                } else {
                    println!("[srp] 2FA OK, retry login sau 3s...");
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    return self.authenticate(gsa, twofa, apple_id, password, depth + 1);
                }
            }
        }

        let dsid = extract_string(&spd_data, &["adsid", "dsid"]);

        let app_token = if let (Some(adsid), Some(c2), Some(sk), Some(idms)) = (
            extract_string(&spd_data, &["adsid"]),
            extract_string(&spd_data, &["c"]),
            spd_data.get("sk").and_then(|v| v.as_data()),
            extract_string(&spd_data, &["GsIdmsToken", "idmsToken"]),
        ) {
            match self.fetch_app_token(gsa, &adsid, &c2, &idms, sk, &session_key) {
                Ok(Some(t)) => {
                    println!("[srp] App token OK");
                    Some(t)
                }
                Ok(None) => None,
                Err(e) => {
                    println!("[srp] Fetch app token that bai: {}", e);
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
        const APP: &str = APP_XCODE_AUTH;

        let mut mac = Hmac::<Sha256>::new_from_slice(sk).map_err(|e| anyhow!("HMAC init: {}", e))?;
        mac.update(b"apptokens");
        mac.update(adsid.as_bytes());
        mac.update(APP.as_bytes());
        let checksum = mac.finalize().into_bytes().to_vec();

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("u".into(), Value::String(adsid.to_string()));
        params.insert("app".into(), Value::Array(vec![Value::String(APP.to_string())]));
        params.insert("c".into(), Value::String(c.to_string()));
        params.insert("t".into(), Value::String(idms_token.to_string()));
        params.insert("checksum".into(), Value::Data(checksum));
        params.insert("o".into(), Value::String("apptokens".into()));

        println!("[srp] Gui apptokens request...");
        let resp = gsa.request(params, 1)?;

        let et = resp
            .get("et")
            .and_then(|v| v.as_data())
            .ok_or_else(|| anyhow!("Response thieu 'et'"))?;

        let decrypted = decrypt_gcm(session_key, et).context("Decrypt et GCM that bai")?;

        let plist_val: Value = plist::from_bytes(&decrypted).context("Parse et plist that bai")?;

        let app_tokens = plist_val
            .as_dictionary()
            .and_then(|d| d.get("t"))
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("et thieu 't'"))?;

        let token_info = app_tokens
            .get(APP)
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| anyhow!("Khong co token cho {}", APP))?;

        let token = token_info
            .get("token")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        Ok(token)
    }
}

fn extract_string(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = dict.get(*k).and_then(|v| v.as_string()) {
            return Some(s.to_string());
        }
    }
    None
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
