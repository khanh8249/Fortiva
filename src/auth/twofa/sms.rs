// src/auth/twofa/sms.rs
use anyhow::{anyhow, Result};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use serde_json::json;
use std::time::Duration;

use super::TwoFAHandler;
use crate::auth::anisette::AnisetteClient;
use crate::constants::{PHONE_CODE_URL, PHONE_VERIFY_URL};

pub struct SmsHandler;

impl SmsHandler {
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
        println!("[2fa-sms] SMS flow...");

        let phone_id = self
            .get_phone_id(twofa, anisette, dsid, idms_token, user_id, device_id)
            .unwrap_or(1);

        println!("[2fa-sms] Dùng phone id={}", phone_id);

        self.request_sms(twofa, anisette, dsid, idms_token, user_id, device_id, phone_id)?;

        let code = input_func("[2fa-sms] Nhập mã OTP: ").trim().to_string();
        if code.is_empty() {
            return Ok(false);
        }

        self.verify_code(
            twofa, anisette, dsid, idms_token, user_id, device_id, phone_id, &code,
        )
    }

    fn get_phone_id(
        &self,
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<i64> {
        let headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;

        match twofa
            .client
            .get(PHONE_VERIFY_URL)
            .headers(headers)
            .timeout(Duration::from_secs(10))
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                let val: serde_json::Value = resp.json()?;
                if let Some(phones) = val.get("trustedPhoneNumbers").and_then(|p| p.as_array()) {
                    if let Some(first) = phones.first() {
                        if let Some(id) = first.get("id").and_then(|i| i.as_i64()) {
                            return Ok(id);
                        }
                    }
                }
                Ok(1)
            }
            _ => Ok(1),
        }
    }

    fn request_sms(
        &self,
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        phone_id: i64,
    ) -> Result<()> {
        let mut headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = json!({
            "phoneNumber": { "id": phone_id },
            "mode": "sms"
        });

        let resp = twofa
            .client
            .put(PHONE_VERIFY_URL)
            .headers(headers)
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()?;

        if !resp.status().is_success() {
            return Err(anyhow!("Request SMS thất bại: HTTP {}", resp.status()));
        }

        println!("[2fa-sms] Đã gửi SMS");
        Ok(())
    }

    fn verify_code(
        &self,
        twofa: &mut TwoFAHandler,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<bool> {
        let mut headers = twofa.build_2fa_headers(anisette, dsid, idms_token, user_id, device_id)?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = json!({
            "phoneNumber": { "id": phone_id },
            "mode": "sms",
            "securityCode": { "code": code }
        });

        let resp = twofa
            .client
            .post(PHONE_CODE_URL)
            .headers(headers)
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()?;

        if resp.status().is_success() {
            println!("[2fa-sms] SMS OK!");
            Ok(true)
        } else {
            eprintln!("[2fa-sms] Fail: HTTP {}", resp.status());
            Ok(false)
        }
    }
}
