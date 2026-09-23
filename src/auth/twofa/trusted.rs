// src/auth/twofa/trusted.rs
use anyhow::{anyhow, Result};
use plist::Value;
use std::time::Duration;

use super::TwoFAHandler;
use crate::auth::anisette::AnisetteClient;
use crate::constants::{GSA_VALIDATE_URL, TRUSTED_DEVICE_URL};

pub struct TrustedDeviceHandler;

impl TrustedDeviceHandler {
    pub fn handle(
        &self,
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
    ) -> Result<bool> {
        println!("[2fa] Trusted device flow...");

        let mut headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;

        eprintln!("[DBG-2FA-TRUSTED] === Request headers ===");
        for (k, v) in headers.iter() {
            eprintln!("[DBG-2FA-TRUSTED]   {}: {:?}", k, v);
        }
        eprintln!("[DBG-2FA-TRUSTED] ==========================");

        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(2));
            }
            match twofa
                .client
                .get(TRUSTED_DEVICE_URL)
                .headers(headers.clone())
                .timeout(Duration::from_secs(15))
                .send()
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 412 {
                        println!("[2fa] Push sent (HTTP {})", status);
                        break;
                    }
                    let body = resp.text().unwrap_or_default();
                    eprintln!("[DBG-2FA-BODY] HTTP {} body: {}", status, body);
                    println!("[2fa] HTTP {} (attempt {}/3)", status, attempt + 1);
                }
                Err(e) => {
                    println!("[2fa] Push loi: {} (attempt {}/3)", e, attempt + 1);
                    if attempt == 2 {
                        return Err(anyhow!("Trusted device push failed"));
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }

        let code = input_func("[2fa] Nhap ma 6 so tu iPhone: ").trim().to_string();
        if code.is_empty() {
            return Ok(false);
        }

        headers.insert(
            "security-code",
            reqwest::header::HeaderValue::from_str(&code)?,
        );

        let resp = twofa
            .client
            .post(GSA_VALIDATE_URL)
            .headers(headers)
            .body("")
            .timeout(Duration::from_secs(15))
            .send()?;

        let status = resp.status();

        if status.is_success() {
            let bytes = resp.bytes()?;
            match plist::from_bytes::<Value>(&bytes) {
                Ok(val) => {
                    let ec = val
                        .as_dictionary()
                        .and_then(|d| d.get("Response"))
                        .and_then(|r| r.as_dictionary())
                        .and_then(|d| d.get("Status"))
                        .and_then(|s| s.as_dictionary())
                        .and_then(|d| d.get("ec"))
                        .and_then(plist_integer)
                        .unwrap_or(0);

                    if ec == 0 {
                        println!("[2fa] Trusted device OK!");
                        return Ok(true);
                    }
                    eprintln!("[2fa] ec={}", ec);
                }
                Err(_) => {
                    println!("[2fa] HTTP OK (khong parse duoc plist)");
                    return Ok(true);
                }
            }
        }

        eprintln!("[2fa] Fail: {}", status);
        Ok(false)
    }
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
