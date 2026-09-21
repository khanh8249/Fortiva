// src/dev/app_ids.rs
use anyhow::{anyhow, Context, Result};
use plist::Value;
use std::collections::HashMap;

use super::client::{DeveloperClient, DevError};
use crate::auth::anisette::AnisetteClient;

#[derive(Debug, Clone)]
pub struct AppId {
    pub identifier: String,
    pub app_id_id: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub encoded_profile: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AppGroup {
    pub group_id: String,
    pub name: String,
    pub app_group_id: Option<String>,
}

// ============================================================
//  APP ID APIs
// ============================================================

impl DeveloperClient {
    /// List tất cả App ID của team.
    pub fn list_app_ids_full(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<AppId>> {
        let resp = self
            .request_plist(auth, "ios/listAppIds.action", HashMap::new(), true)
            .context("listAppIds thất bại")?;

        let apps = resp
            .get("appIds")
            .and_then(|v| v.as_array())
            .map(|arr| arr.to_vec())
            .unwrap_or_default();

        let mut out = Vec::new();
        for a in apps {
            let dict = match a.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            let identifier = dict
                .get("identifier")
                .or_else(|| dict.get("bundleId"))
                .or_else(|| dict.get("bundleID"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();

            let app_id_id = dict
                .get("appIdId")
                .or_else(|| dict.get("id"))
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let name = dict
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("(unknown)")
                .to_string();

            if !identifier.is_empty() {
                out.push(AppId {
                    identifier,
                    app_id_id,
                    name,
                });
            }
        }

        Ok(out)
    }

    /// Tạo App ID mới.
    pub fn create_app_id_full(
        &mut self,
        auth: &mut AnisetteClient,
        bundle_id: &str,
        name: &str,
    ) -> Result<AppId> {
        let sanitized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
            .collect();
        let sanitized = if sanitized.is_empty() {
            "App".to_string()
        } else {
            sanitized
        };

        let mut params = HashMap::new();
        params.insert("identifier".into(), Value::String(bundle_id.to_string()));
        params.insert("name".into(), Value::String(sanitized));

        let resp = self
            .request_plist(auth, "ios/addAppId.action", params, true)
            .context("addAppId thất bại")?;

        let app_id = resp
            .get("appId")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| {
                let err = DevError {
                    result_code: resp
                        .get("resultCode")
                        .and_then(|v| v.as_signed_integer()),
                    user_string: resp
                        .get("userString")
                        .or_else(|| resp.get("resultString"))
                        .and_then(|v| v.as_string())
                        .unwrap_or("?")
                        .to_string(),
                };
                anyhow!("addAppId thất bại: {:?}", err)
            })?;

        Ok(AppId {
            identifier: app_id
                .get("identifier")
                .and_then(|v| v.as_string())
                .unwrap_or(bundle_id)
                .to_string(),
            app_id_id: app_id
                .get("appIdId")
                .or_else(|| app_id.get("id"))
                .and_then(|v| v.as_string())
                .map(|s| s.to_string()),
            name: app_id
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("App")
                .to_string(),
        })
    }

    /// Đảm bảo có App ID.
    pub fn ensure_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        bundle_id: &str,
        name: &str,
    ) -> Result<AppId> {
        let existing = self.list_app_ids_full(auth)?;
        if let Some(a) = existing.iter().find(|a| a.identifier == bundle_id) {
            println!("[dev] App ID đã có: {}", bundle_id);
            return Ok(a.clone());
        }

        println!("[dev] Tạo App ID: {}", bundle_id);
        self.create_app_id_full(auth, bundle_id, name)
    }

    /// Xóa App ID.
    pub fn delete_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        app_id_id: &str,
    ) -> Result<bool> {
        let mut params = HashMap::new();
        params.insert("appIdId".into(), Value::String(app_id_id.to_string()));
        
        match self.request_plist(auth, "ios/deleteAppId.action", params, true) {
        }
