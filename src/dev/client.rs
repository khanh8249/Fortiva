// src/dev/client.rs
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use plist::{Dictionary, Value};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::auth::AnisetteClient;

pub const BASE_URL_QH65B2: &str = "https://developerservices2.apple.com/services/QH65B2";
pub const BASE_URL_V1: &str = "https://developerservices2.apple.com/services/v1";
pub const CLIENT_ID: &str = "XABBG36SBA";
pub const PROTOCOL_VERSION: &str = "QH65B2";
pub const XCODE_VERSION: &str = "11.2 (11B41)";

pub struct DeveloperClient {
    pub dsid: String,
    pub session_token: String,
    pub team_id: Option<String>,
    pub last_error: Option<DevError>,
    pub client: Client,
    pub anisette: AnisetteCache,
}

#[derive(Debug, Clone)]
pub struct DevError {
    pub result_code: Option<i64>,
    pub user_string: String,
}

/// Cache anisette headers riêng cho DeveloperClient (60s).
pub struct AnisetteCache {
    cached: Option<HashMap<String, String>>,
    cache_time: Option<Instant>,
}

impl AnisetteCache {
    pub fn new() -> Self {
        Self { cached: None, cache_time: None }
    }

    pub fn get(
           &mut self,
        auth: &mut AnisetteClient,
        force: bool,
    ) -> Result<HashMap<String, String>> {
        if !force {
        if let (Some(c), Some(t)) = (&self.cached, self.cache_time) {
                if t.elapsed() < Duration::from_secs(60) {
                    return Ok(c.clone());
                }
            }
        self }
        let fresh = auth.fetch(true)?;
        self.cached = Some(fresh.clone());
        self.cache_time = Some(Instant::now());
        Ok(fresh)
    }
}

impl DeveloperClient {
    pub fn new(dsid: String, session_token: String) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            dsid,
            session_token,
            team_id: None,
            last_error: None,
            client,
            anisette: AnisetteCache::new(),
        })
    }

    pub fn set_team(&mut self, team_id: String) {
        self.team_id = Some(team_id);
    }

    /// Build auth headers cho request QH65B2 (plist).
    pub fn auth_headers_plist(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
    ) -> Result<HeaderMap> {
        self.build_headers(
            auth,
            force_anisette,
            "text/x-xml-plist",
            "text/x-xml-plist",
        )
    }

    /// Build auth headers cho request JSON (v1 API).
    pub fn auth_headers_json(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
    ) -> Result<HeaderMap> {
        self.build_headers(
            auth,
            force_anisette,
            "application/vnd.api+json",
            "application/vnd.api+json",
        )
    }

    fn build_headers(
        &mut self,
        auth: &mut AnisetteClient,
        force_anisette: bool,
        content_type: &str,
        accept: &str,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type)?,
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_str(accept)?,
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("Xcode"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-us"),
        );
        headers.insert(
            "X-Apple-App-Info",
            HeaderValue::from_static("com.apple.gs.xcode.auth"),
        );
        headers.insert(
            "X-Xcode-Version",
            HeaderValue::from_static(XCODE_VERSION),
        );
        headers.insert(
            "X-Apple-I-Identity-Id",
            HeaderValue::from_str(&self.dsid)?,
        );
        headers.insert(
            "X-Apple-GS-Token",
            HeaderValue::from_str(&self.session_token)?,
        );

        // Anisette headers
        let anisette = self.anisette.get(auth, force_anisette)?;
        for (k, v) in anisette {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                headers.insert(name, value);
            }
        }

        Ok(headers)
    }

    /// Gửi request plist QH65B2. Có retry 2 lần, tự refresh anisette khi ec=1100.
    pub fn request_plist(
        &mut self,
        auth: &mut AnisetteClient,
        action: &str,
        extra_params: HashMap<String, Value>,
        require_team: bool,
    ) -> Result<Dictionary> {
        for attempt in 0..2 {
            let headers = self.auth_headers_plist(auth, false)?;

            let mut params = Dictionary::new();
            params.insert("clientId".into(), Value::String(CLIENT_ID.into()));
            params.insert(
                "protocolVersion".into(),
                Value::String(PROTOCOL_VERSION.into()),
            );
            params.insert(
                "requestId".into(),
                Value::String(Uuid::new_v4().to_string().to_uppercase()),
            );

            if require_team {
                let team = self
                    .team_id
                    .as_ref()
                    .ok_or_else(|| anyhow!("Chưa có team_id"))?;
                params.insert("teamId".into(), Value::String(team.clone()));
            }

            for (k, v) in &extra_params {
                params.insert(k.clone(), v.clone());
            }

            let url = format!("{}/{}?clientId={}", BASE_URL_QH65B2, action, CLIENT_ID);
            let body = plist::to_writer_xml(
                &mut Vec::new(),
                &Value::Dictionary(params),
            )
            .map_err(|e| anyhow!("Plist encode: {}", e))?;

            let resp = self.client.post(&url).headers(headers).body(body).send();

            match resp {
                Ok(r) => {
                    if r.status().as_u16() >= 500 {
                        eprintln!("[DevAPI] Lỗi {} - thử lại...", r.status());
                        std::thread::sleep(Duration::from_secs(2));
                        continue;
                    }

                    let bytes = r.bytes()?;
                    let plist_val: Value = plist::from_bytes(&bytes)?;
                    let dict = plist_val
                        .as_dictionary()
                        .ok_or_else(|| anyhow!("Response không phải dict"))?
                        .clone();

                    let result_code = dict
                        .get("resultCode")
                        .or_else(|| dict.get("resultcode"))
                        .and_then(|v| v.as_signed_integer());

                    if result_code == Some(1100) && attempt == 0 {
                        eprintln!("[DevAPI] anisette expired (1100) - refresh...");
                        self.anisette.get(auth, true)?;
                        continue;
                    }

                    return Ok(dict);
                }
                Err(e) => {
                    if attempt == 0 {
                        eprintln!("[DevAPI] Lỗi lần 1: {} - thử lại...", e);
                        self.anisette.get(auth, true)?;
                        continue;
                    }
                    return Err(anyhow!("Request {} thất bại: {}", action, e));
                }
            }
        }

        Err(anyhow!("Request {} thất bại sau 2 lần", action))
    }

    /// Gửi request JSON v1 API (dùng cho certificates).
    pub fn request_json(
        &mut self,
        auth: &mut AnisetteClient,
        method_override: &str,
        url: &str,
        query: &str,
    ) -> Result<serde_json::Value> {
        let headers = self.auth_headers_json(auth, true)?;

        let req = self
            .client
            .post(url)
            .headers(headers)
            .header("X-HTTP-Method-Override", method_override)
            .json(&serde_json::json!({ "urlEncodedQueryParams": query }));

        let resp = req.send()?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "JSON API {} thất bại: {}",
                url,
                resp.status()
            ));
        }

        Ok(resp.json()?)
    }
}