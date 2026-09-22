// src/auth/twofa/trusted.rs
use anyhow::{anyhow, Result};
use plist::Value;
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use std::time::Duration;

use crate::auth::anisette::AnisetteClient;
use crate::constants::{GSA_VALIDATE_URL, TRUSTED_DEVICE_URL};

pub struct TrustedDeviceHandler;

impl TrustedDeviceHandler {
    pub fn handle(
        &self,
        client: &Client,
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        input_func: &dyn Fn(&str) -> String,
        client_info: &str,
    ) -> Result<bool> {
        println!("[2fa] Trusted device...");

        let mut headers = Self::build_headers(
            anisette, dsid, idms_token, user_id, device_id, client_info,
        )?;

        for attempt in 0..3 {
            match client
                .get(TRUSTED_DEVICE_URL)
                .headers(headers.clone())
                .timeout(Duration::from_secs(15))
                .send()
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 412 {
                        break;
                    }
                }
                Err(_) => {
                    if attempt == 2 {
                        return Err(anyhow!("Trusted device request failed"));
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }

        let code = input_func("[2fa] Nhap ma 6 so: ").trim().to_string();
        if code.is_empty() {
            return Ok(false);
        }

        headers.insert(
            "security-code",
            reqwest::header::HeaderValue::from_str(&code)?,
        );

        let resp = client
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
                        .and_then(|v| v.as_signed_integer())
                        .unwrap_or(0);

                    if ec == 0 {
                        println!("[2fa] OK!");
                        return Ok(true);
                    }
                    eprintln!("[2fa] ec={}", ec);
                }
                Err(_) => {
                    return Ok(true);
                }
            }
        }

        eprintln!("[2fa] Fail: {}", status);
        Ok(false)
    }

    fn build_headers(
        anisette: &mut AnisetteClient,
        dsid: &str,
        idms_token: &str,
        user_id: &str,
        device_id: &str,
        client_info: &str,
    ) -> Result<HeaderMap> {
        use base64::{engine::general_purpose, Engine as _};
        use reqwest::header::{HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};

        use crate::constants::{APP_XCODE_AUTH, XCODE_UA};

        let mut headers = HeaderMap::new();

        let identity_token = general_purpose::STANDARD
            .encode(format!("{}:{}", dsid, idms_token).as_bytes());

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
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
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
