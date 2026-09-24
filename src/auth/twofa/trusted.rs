// src/auth/twofa/trusted.rs
use anyhow::{anyhow, Result};
use plist::Value;
use reqwest::header::HeaderValue;
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

        let headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;

        // ============================================================
        //  DEBUG: in headers gửi đi (REDACTED)
        // ============================================================
        eprintln!("[DBG-RUST-2FA] === Request headers ===");
        for (k, v) in headers.iter() {
            let key_str = k.as_str().to_lowercase();
            let val_str = v.to_str().unwrap_or("<binary>");
            let shown = match key_str.as_str() {
                "x-apple-identity-token"
                | "x-apple-i-md"
                | "x-apple-i-md-m"
                | "x-apple-i-md-lu"
                | "x-mme-device-id"
                | "x-apple-i-dsid" => "<REDACTED>".to_string(),
                _ => val_str.to_string(),
            };
            eprintln!("[DBG-RUST-2FA]   {}: {}", key_str, shown);
        }
        eprintln!("[DBG-RUST-2FA] ==========================");
        // ============================================================

        // ============================================================
        //  BƯỚC 1: Test redirect — Client KHÔNG follow redirect
        // ============================================================
        {
            let client_no_redirect = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(15))
                .pool_max_idle_per_host(0)
                .no_proxy()
                .http1_only()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            eprintln!("[DBG-RUST-2FA] === Test redirect (Policy::none) ===");
            match client_no_redirect
                .get(TRUSTED_DEVICE_URL)
                .headers(headers.clone())
                .send()
            {
                Ok(resp) => {
                    let status = resp.status();
                    let version = resp.version();
                    let url = resp.url().clone();
                    let resp_headers = resp.headers().clone();
                    let body = resp.bytes()?;

                    eprintln!("[DBG-RUST-2FA] status={}", status);
                    eprintln!("[DBG-RUST-2FA] version={:?}", version);
                    eprintln!("[DBG-RUST-2FA] url={}", url);
                    eprintln!("[DBG-RUST-2FA] --- response headers ---");
                    for (k, v) in resp_headers.iter() {
                        eprintln!("[DBG-RUST-2FA]   {}: {:?}", k, v);
                    }
                    eprintln!("[DBG-RUST-2FA] body_len={}", body.len());
                    eprintln!(
                        "[DBG-RUST-2FA] body={}",
                        String::from_utf8_lossy(&body[..body.len().min(500)])
                    );

                    // Nếu có Location header → có redirect
                    if let Some(loc) = resp_headers.get("location") {
                        eprintln!("[DBG-RUST-2FA] REDIRECT detected → {:?}", loc);
                    }
                }
                Err(e) => {
                    eprintln!("[DBG-RUST-2FA] redirect test error: {}", e);
                }
            }
            eprintln!("[DBG-RUST-2FA] ==========================");
        }

        // ============================================================
        //  BƯỚC 2: Send push 2FA (client thường, follow redirect)
        // ============================================================
        let mut success = false;

        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(2));
            }

            eprintln!("[DBG-RUST-2FA] === Attempt {}/3 ===", attempt + 1);

            match twofa
                .client
                .get(TRUSTED_DEVICE_URL)
                .headers(headers.clone())
                .timeout(Duration::from_secs(15))
                .send()
            {
                Ok(resp) => {
                    let status = resp.status();
                    let version = resp.version();
                    let url = resp.url().clone();
                    let resp_headers = resp.headers().clone();
                    let body = resp.bytes()?;

                    eprintln!("[DBG-RUST-2FA] status={}", status);
                    eprintln!("[DBG-RUST-2FA] version={:?}", version);
                    eprintln!("[DBG-RUST-2FA] url={}", url);
                    eprintln!("[DBG-RUST-2FA] --- response headers ---");
                    for (k, v) in resp_headers.iter() {
                        eprintln!("[DBG-RUST-2FA]   {}: {:?}", k, v);
                    }
                    eprintln!("[DBG-RUST-2FA] body_len={}", body.len());
                    eprintln!(
                        "[DBG-RUST-2FA] body={}",
                        String::from_utf8_lossy(&body[..body.len().min(500)])
                    );

                    let code = status.as_u16();
                    if code == 200 || code == 412 {
                        println!("[2fa] Push sent (HTTP {})", code);
                        success = true;
                        break;
                    }
                    println!("[2fa] HTTP {} (attempt {}/3)", code, attempt + 1);
                }
                Err(e) => {
                    eprintln!("[DBG-RUST-2FA] error: {}", e);
                    println!("[2fa] Push loi: {} (attempt {}/3)", e, attempt + 1);
                    if attempt == 2 {
                        return Err(anyhow!("Trusted device push failed"));
                    }
                }
            }
        }

        if !success {
            eprintln!("[DBG-RUST-2FA] Push không thành công sau 3 lần");
            // Vẫn cho user nhập mã (Apple có thể gửi push dù status không phải 200/412)
        }

        // ============================================================
        //  BƯỚC 3: User nhập mã 6 số
        // ============================================================
        let code = input_func("[2fa] Nhap ma 6 so tu iPhone: ").trim().to_string();
        if code.is_empty() {
            return Ok(false);
        }

        // ============================================================
        //  BƯỚC 4: Verify code
        // ============================================================
        let mut verify_headers = twofa.build_2fa_headers(
            anisette, dsid, idms_token, user_id, device_id,
        )?;
        verify_headers.insert(
            "security-code",
            HeaderValue::from_str(&code)?,
        );

        eprintln!("[DBG-RUST-2FA] === Verify code ===");
        eprintln!("[DBG-RUST-2FA] url={}", GSA_VALIDATE_URL);

        let resp = twofa
            .client
            .post(GSA_VALIDATE_URL)
            .headers(verify_headers)
            .body("")
            .timeout(Duration::from_secs(15))
            .send()?;

        let status = resp.status();
        let version = resp.version();
        let url = resp.url().clone();
        let _resp_headers = resp.headers().clone();
        let body = resp.bytes()?;

        eprintln!("[DBG-RUST-2FA] status={}", status);
        eprintln!("[DBG-RUST-2FA] version={:?}", version);
        eprintln!("[DBG-RUST-2FA] url={}", url);
        eprintln!("[DBG-RUST-2FA] body_len={}", body.len());
        eprintln!(
            "[DBG-RUST-2FA] body={}",
            String::from_utf8_lossy(&body[..body.len().min(500)])
        );

        if status.is_success() {
            match plist::from_bytes::<Value>(&body) {
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
