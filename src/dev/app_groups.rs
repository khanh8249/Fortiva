// src/dev/app_groups.rs
use anyhow::{anyhow, Context, Result};
use plist::Value;
use std::collections::HashMap;

use super::client::{DeveloperClient, DevError};
use crate::auth::anisette::AnisetteClient;

#[derive(Debug, Clone)]
pub struct AppGroup {
    pub group_id: String,
    pub name: String,
    pub app_group_id: Option<String>,
}

impl DeveloperClient {
    /// List App Group hiện có.
    pub fn list_app_groups(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<AppGroup>> {
        let resp = self
            .request_plist(auth, "ios/listAppGroups.action", HashMap::new(), true)
            .context("listAppGroups thất bại")?;

        let groups = resp
            .get("appGroups")
            .and_then(|v| v.as_array())
            .map(|arr| arr.to_vec())
            .unwrap_or_default();

        let mut out = Vec::new();
        for g in groups {
            let dict = match g.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            let group_id = dict
                .get("identifier")
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();

            if group_id.is_empty() {
                continue;
            }

            out.push(AppGroup {
                group_id,
                name: dict
                    .get("name")
                    .and_then(|v| v.as_string())
                    .unwrap_or("(unknown)")
                    .to_string(),
                app_group_id: dict
                    .get("appGroupId")
                    .or_else(|| dict.get("id"))
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_string()),
            });
        }

        Ok(out)
    }

    /// Tạo App Group mới.
    pub fn create_app_group(
        &mut self,
        auth: &mut AnisetteClient,
        group_id: &str,
        name: &str,
    ) -> Result<AppGroup> {
        let sanitized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
            .collect();
        let sanitized = if sanitized.is_empty() {
            "App Group".to_string()
        } else {
            sanitized
        };

        let mut params = HashMap::new();
        params.insert("identifier".into(), Value::String(group_id.to_string()));
        params.insert("name".into(), Value::String(sanitized));

        let resp = self
            .request_plist(auth, "ios/addAppGroup.action", params, true)
            .context("addAppGroup thất bại")?;

        let group = resp
            .get("appGroup")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| {
                anyhow!(
                    "addAppGroup thất bại: resultCode={:?} userString={:?}",
                    resp.get("resultCode").and_then(|v| v.as_signed_integer()),
                    resp.get("userString").and_then(|v| v.as_string())
                )
            })?;

        Ok(AppGroup {
            group_id: group
                .get("identifier")
                .and_then(|v| v.as_string())
                .unwrap_or(group_id)
                .to_string(),
            name: group
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("App Group")
                .to_string(),
            app_group_id: group
                .get("appGroupId")
                .or_else(|| group.get("id"))
                .and_then(|v| v.as_string())
                .map(|s| s.to_string()),
        })
    }

    /// Đảm bảo App Group tồn tại (tạo nếu chưa).
    pub fn ensure_app_group(
        &mut self,
        auth: &mut AnisetteClient,
        group_id: &str,
        name: &str,
    ) -> Result<AppGroup> {
        let existing = self.list_app_groups(auth)?;
        if let Some(g) = existing.iter().find(|g| g.group_id == group_id) {
            println!("[dev] App Group đã có: {}", group_id);
            return Ok(g.clone());
        }

        println!("[dev] Tạo App Group: {}", group_id);
        self.create_app_group(auth, group_id, name)
    }
}
