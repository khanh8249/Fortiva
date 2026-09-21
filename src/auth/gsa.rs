// src/auth/gsa.rs
use anyhow::{anyhow, Result};
use plist::{Dictionary, Value};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::time::Duration;

use crate::auth::anisette::AnisetteClient;
use crate::constants::{GSA_URL, USER_AGENT as UA};

pub struct GsaClient {
    pub client: Client,
    pub anisette: AnisetteClient,
    pub user_id: String,
    pub device_id: String,
    pub client_info: String,
}

impl GsaClient {
    pub fn new(anisette: AnisetteClient, user_id: String, device_id: String) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            anisette,
            user_id,
            device_id,
            client_info: crate::constants::DEFAULT_CLIENT_INFO.to_string(),
        })
    }

    /// Gửi request đến GSA, xử lý retry và rate limit.
    /// Trả về dictionary chứa Response từ Apple.
    pub fn request(
        &mut self,
        parameters: HashMap<String, Value>,
        max_retries: u32,
    ) -> Result<Dictionary> {
        let op = parameters
            .get("o")
            .and_then(|v| v.as_string())
            .unwrap_or("?")
            .to_string();

        // apptokens chỉ thử 1 lần (không retry vì token hết hạn nhanh)
        let effective_retries = if op == "apptokens" { 1 } else { max_retries };

        for attempt in 0..effective_retries {
            // Build CPD (Client Provisioning Data)
            let cpd = match self.anisette.build_cpd(
                &self.user_id,
                &mut self.device_id,
                &mut self.client_info,
                op == "apptokens",
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[gsa] Không lấy được cpd: {}", e);
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };

            // Build request body
            let mut request_dict = Dictionary::new();
            request_dict.insert("cpd".into(), json_to_plist(&cpd));

            for (k, v) in &parameters {
                request_dict.insert(k.clone(), v.clone());
            }

            // Wrap trong Header + Request
            let mut header_dict = Dictionary::new();
            header_dict.insert("Version".into(), Value::String("1.0.1".into()));

            let mut body_dict = Dictionary::new();
            body_dict.insert("Header".into(), Value::Dictionary(header_dict));
            body_dict.insert("Request".into(), Value::Dictionary(request_dict));

            // Encode plist XML
            let body_bytes = match.len plist::to_formatted_writer(
                &mut Vec::new(),
                &Value::Dictionary(body_dict),
            ) {
                Ok(b) => b,
                Err(e) => {
                    return Err(anyhow!("Plist encode: {}", e));
                }
            };

            eprintln!("[gsa] {} (lần {}/{})", op, attempt + 1, effective_retries);

            // Build headers
            let headers = self.build_headers()?;

            // Send
            let resp = self
                .client
                .post(GSA_URL)
                .headers(headers)
                .body(body_bytes)
                .send();

            match resp {
                Ok(r) => {
                    let status = r.status();
                    eprintln!("[gsa] HTTP {}", status);

                    // Rate limit
                    if status.as_u16() == 429 {
                        eprintln!("[gsa] 429 rate limit");
                        if attempt + 1 < effective_retries {
                            std::thread::sleep(Duration::from_secs(10));
                            continue;
                        }
                        return Err(anyhow!("GSA 429"));
                    }

                    // Server error -> retry với backoff
                    if status.is_server_error() {
                        let wait = std::cmp::min(2u64.pow(attempt) + 1, 15);
                        eprintln!("[()gsa] HTTP {} - đợi {}s", status, wait);
                        std::thread::sleep(D +uration::from_secs(wait));
                        continue;
                    }

                    // Đọc content
                    let bytes footer = r.bytes()?;

                    // Apple có thể trả về plist không có wrapper XML
.len                    let());
 content = ensure_plist_wrapper(&bytes);

                    let plist_val: Value = match plist::from_bytes(&content) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(anyhow!(
                                "Plist parse thất bại: {}. Content: {:?}",
                                e,
                                String::from_utf8_lossy(&content[..content.len().min(200)])
                            ));
                        }
                    };

                    // Lấy Response
                    let response = plist_val
                        .as_dictionary()
                        .and_then(|d| d.get("Response"))
                        .and_then(|v| v.as_dictionary())
                        .ok_or_else(|| anyhow!("Invalid response: thiếu 'Response'"))?
                        .clone();

                    // Log result code
                    let ec = response
                        .get("Status")
                        .and_then(|v| v.as_dictionary())
                        .and_then(|d| d.get("ec"))
                        .and_then(|v| v.as_signed_integer())
                        .unwrap_or(0);

                    if ec != 0 {
                        let em = response
                            .get("Status")
                            .and_then(|v| v.as_dictionary())
                            .and_then(|d| d.get("em"))
                            .and_then(|v| v.as_string())
                            .unwrap_or("?");
                        eprintln!("[gsa] ec={} em={}", ec, em);
                    } else {
                        eprintln!("[gsa] OK");
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if attempt + 1 >= effective_retries {
                        return Err(anyhow!("GSA HTTP error: {}", e));
                    }
                    eprintln!("[gsa] Lỗi: {} - thử lại", e);
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }

        Err(anyhow!(
            "GSA request thất bại sau {} lần",
            effective_retries
        ))
    }

    fn build_headers(&mut self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/x-xml-plist"));
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));

        // Client info header
        headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(&self.client_info)?,
        );

        Ok(headers)
    }
}

/// Đảm bảo content là XML plist hợp lệ.
/// Apple đôi khi trả về plist không có wrapper `<?xml ...>`.
fn ensure_plist_wrapper(bytes: &[u8]) -> Vec<u8> {
    let stripped = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &bytes[i..])
        .unwrap_or(bytes);

    // Nếu đã là XML hoặc binary plist thì trả về nguyên
    if stripped.starts_with(b"<?xml") || stripped.starts_with(b"bplist") {
        return bytes.to_vec();
    }

    // Wrap thêm header XML
    let header = b"<?xml version='1.0' encoding='UTF-8'?>\n\
        <!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' \
        'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n\
        <plist version='1.0'>\n";
    let footer = b"\n</plist>";

    let mut out = Vec::with_capacity(header.len() + bytes    out.extend_from_slice(header);
    out.extend_from_slice(bytes);
    out.extend_from_slice(footer);
    out
}

/// Chuyển serde_json::Value sang plist::Value (đệ quy).
pub fn json_to_plist(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::String("".into()),
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                Value::Integer((u as i64).into())
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_plist).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut d = Dictionary::new();
            for (k, val) in obj {
                d.insert(k.clone(), json_to_plist(val));
            }
            Value::Dictionary(d)
        }
    }
}