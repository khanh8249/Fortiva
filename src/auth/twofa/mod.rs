// src/auth/twofa/mod.rs
mod sms;
mod trusted;

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;

use crate::auth::anisette::AnisetteClient;
use crate::constants::{XCODE_UA, DEFAULT_CLIENT_INFO, APP_XCODE_AUTH};

pub use trusted::TrustedDeviceHandler;
pub use sms::SmsHandler;

/// Orchestrator cho 2FA - tự chọn handler dựa trên auth_type.
pub struct TwoFAHandler {
    pub client: reqwest::blocking::Client,
    pub client_info: String,
}

impl TwoFAHandler {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client");

        Self {
            client,
            client_info: DEFAULT_CLIENT_INFO.to_string(),
        }
    }

    /// Xây dựng headers cho 2FA request (dùng chung).
    pub fn build_2fa_headers(
        &mut self,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        // Identity token = base64(dsid:idms_token)
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
            HeaderValue::from_str(&self.client_info)?,
        );
        headers.insert("X-Apple-I-DSID", HeaderValue::from_str(dsid)?);

        // Meta headers
        let meta = AnisetteClient::get_meta_headers(user_id, device_id);
        for (k, v) in meta {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                headers.insert(name, value);
            }
        }

        // Anisette headers (MD, MD-M, MD-LU, MD-RINFO, device id)
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
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, value);
                }
            }
        }

        // Override MD-LU = base64(dsid)
        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&general_purpose::STANDARD.encode(dsid.as_bytes()))?,
        );

        Ok(headers)
    }

    /// Tự động chọn handler dựa trên auth_type từ GSA response.
    pub fn handle_2fa(
        &mut self,
        anisette: &mut AnisetteClient,
        auth_type: &str,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
    ) -> Result<bool> {
        match auth_type {
            "trustedDeviceSecondaryAuth" | "secondaryAuth" => {
                // Thử trusted device trước, fallback SMS
                let trusted = TrustedDeviceHandler;
                if trusted.handle(
                    &self.client,
                    anisette,
                    dsid,
                    idms_token,
                    user_id,
                    device_id,
                    input_func,
                    &self.client_info,
                )? {
                    return Ok(true);
                }

                let sms = SmsHandler;
                sms.handle(
                    &self.client,
                    anisette,
                    dsid,
                    idms_token,
                    user_id,
                    device_id,
                    input_func,
                    &self.client_info,
                )
            }
            "smsSecondaryAuth" => {
                // Thử SMS trước, fallback trusted device
                let sms = SmsHandler;
                if sms.handle(
                    &self.client,
                    anisette,
                    dsid,
                    idms_token,
                    user_id,
                    device_id,
                    input_func,
                    &self.client_info,
                )? {
                    return Ok(true);
                }

                let trusted = TrustedDeviceHandler;
                trusted.handle(
                    &self.client,
                    anisette,
                    dsid,
                    idms_token,
                    user_id,
                    device_id,
                    input_func,
                    &self.client_info,
                )
            }
            other => Err(anyhow!("Unknown 2FA type: {}", other)),
        }
    }
}