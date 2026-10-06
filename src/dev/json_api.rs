// src/dev/json_api.rs
use anyhow::{anyhow, Result};
use serde_json::Value;

use super::client::{DeveloperClient, BASE_URL_V1};
use crate::auth::AnisetteClient;

impl DeveloperClient {
    /// Liệt kê tất cả certificate IOS_DEVELOPMENT của team hiện tại.
    pub fn list_certificates(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<Value>> {
        let team_id = self
            .team_id
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa có team_id"))?;

        let url = format!("{}/certificates", BASE_URL_V1);
        let query = format!(
            "teamId={}&filter[certificateType]=IOS_DEVELOPMENT",
            team_id
        );

        let resp = self.request_json(auth, "GET", &url, &query)?;

        Ok(resp
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Thu hồi certificate theo ID.
    pub fn revoke_certificate(
        &mut self,
        auth: &mut AnisetteClient,
        certificate_id: &str,
    ) -> Result<bool> {
        let team_id = self
            .team_id
            .as_ref()
            .ok_or_else(|| anyhow!("Chưa có team_id"))?;

        let url = format!("{}/certificates/{}", BASE_URL_V1, certificate_id);
        let query = format!("teamId={}", team_id);

        match self.request_json(auth, "DELETE", &url, &query) {
            Ok(_) => Ok(true),
            Err(e) => {
                eprintln!("[DevAPI] Revoke thất bại: {}", e);
                Ok(false)
            }
        }
    }

    /// Tìm cert content (base64 DER) theo certificate ID.
    /// Retry nhiều lần vì Apple có delay sau khi tạo cert.
    pub fn fetch_certificate_content(
        &mut self,
        auth: &mut AnisetteClient,
        certificate_id: &str,
    ) -> Result<Option<String>> {
        let delays = [2u64, 4, 6, 8, 10];

        for attempt in 0..delays.len() {
            let certs = self.list_certificates(auth)?;

            for cert in certs {
                if cert.get("id").and_then(|v| v.as_str()) == Some(certificate_id) {
                    if let Some(content) = cert
                        .get("attributes")
                        .and_then(|a| a.get("certificateContent"))
                        .and_then(|c| c.as_str())
                    {
                        return Ok(Some(content.to_string()));
                    }
                }
            }

            if attempt + 1 < delays.len() {
                std::thread::sleep(std::time::Duration::from_secs(delays[attempt]));
            }
        }

        Ok(None)
    }
}