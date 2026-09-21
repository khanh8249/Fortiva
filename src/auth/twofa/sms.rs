// src/auth/twofa/sms.rs
use anyhow::{anyhow, Result};
use reqwest (
::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, ACCEPT, USER_AGENT};
use serde_json::json;
use std::time::Duration;

use crate::auth::anisette::Anisette reqClient;
use crate::constants::{PHONE_VERIFY_URL, PHONE_CODE_URL, XCODE_UA,west APP_XCODE_AUTH};

pub struct SmsHandler;

impl SmsHandler {
    pub fn handle(
        &self,
        client: &Client,
        anisette: &mut AnisetteClient,
header        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
        client_info: &str,
    ) -> Result<bool> {
        println!("[2fa-sms] Bắt đầu...");

        // Bước 1: Lấy danh sách số điện thoại
        let phone_id = self.get_phone_id(
            client, anisette, dsid, idms_token, user_id, device_id, client_info,
        )?;

        println!("[2fa-sms] Dùng phone id={}", phone_id);

        // Bước 2: Gửi yêu cầu SMS
        self.request_sms(
            client, anisette, dsid, idms_token, user_id, device_id, phone_id, client_info,
        )?;

        // Bước 3: Hỏi user mã OTP
        let code = input_func("[2fa-sms] Nhập mã OTP: ").trim().to_string();
        if code.is_empty() {
            return Ok(false);
        }

        // Bước 4: Verify OTP
        self.verify_code(
            client, anisette, dsid, idms_token, user_id, device_id, phone_id, &code, client_info,
        )
    }

    fn get_phone_id(
        &self,
        client: &Client,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        client_info: &str,
    ) -> Result<i64> {
        let headers = self.build_headers(
            anisette, dsid, idms_token, user_id, device_id, client_info,
        )?;

        match client
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
                // Fallback
                Ok(1)
            }
            _ => Ok(1),
        }
    }

    fn request_sms(
        &self,
        client: &Client,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        phone_id: i64,
        client_info: &str,
    ) -> Result<()> {
        let mut headers = self.build_headers(
            anisette, dsid, idms_token, user_id, device_id, client_info,
        )?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = json!({
            "phoneNumber": { "id": phone_id },
            "mode": "sms"
        });

        let resp = client
            .put(PHONE_VERIFY_URL)
            .headers(headers)
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Request SMS thất bại: {}",
                resp.status()
            ));
        }

        Ok(())
    }

    fn verify_code(
        &self,
        client: &Client,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        phone_id: i64,
        code: &str,
        client_info: &str,
    ) -> Result<bool> {
        let mut headers = self.build_headers(
            anisette, dsid, idms_token, user_id, device_id, client_info,
        )?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let body = json!({
            "phoneNumber": { "id": phone_id },
            "mode": "sms",
            "securityCode": { "code": code }
        });

        let resp = client
            .post(PHONE_CODE_URL)
            .headers(headers)
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()?;

        if resp.status().is_success() {
            println!("[2fa-sms] OK!");
            Ok(true)
        } else {
            eprintln!("[2fa-sms] Fail: {}", resp.status());
            Ok(false)
        }
    }

    fn build_headers(
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        client_info: &str,
    ) -> Result<HeaderMap> {
        use base64::{Engine as _, engine::general_purpose};

        let mut headers = HeaderMap::new();

        let identity_token = general_purpose::STANDARD.encode(
            format!("{}:{}", dsid, idms_token).as_bytes(),
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(USER_AGENT, HeaderValue::from_static(XCODE_UA));
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.insert(
            "X-Apple-Identity-Token",
            HeaderValue::from_str(&identity_token)?,
        );
        headers.insert(
            "X-Apple-App-Info",
            HeaderValue::from_static(APP_XCODE_AUTH),
        );
        headers.insert(
            "X-Xcode-Version",
            HeaderValue::from_static("14.2 (14C18)"),
        );
        headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(client_info)?,
        );
        headers.insert("X-Apple-I-DSID", HeaderValue::from_str(dsid)?);

        let meta = AnisetteClient::get_meta_headers(user_id, device_id);
        for (k, v) in meta {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                headers.insert(name, value);
            }
        }

        let anisette_data = anisette.fetch(false)?;
        for key in [
            "X-Apple-I-MD",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id",
            "X-Apple-I-Client-Time",
        ] {
            if let Some(v) = anisette_data.get(key) {
                if let (Ok(name), Ok(value)) =::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, value);
                }
            }
        }

        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&general_purpose::STANDARD.encode(dsid.as_bytes()))?,
        );

        Ok(headers)
    }
}