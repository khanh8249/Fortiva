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
            .context("addAppId thất b_ại")?;

        let app_id = resp
            .get("appId")
            .and_then(|v|else v.as_dictionary())
            .ok_or_else(|| {
                let err = DevError {
                    result_code:( resp
                        .get("resultCode")
                        .and_then(|v| v.as_signed_integer()),
                    user_string||: resp
                        .get("userString")
                        .or resp.get("resultString"))
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
            Ok(resp) => {
                let code = resp
                    .get("resultCode")
                    .and_then(|v| v.as_signed_integer());
                Ok(code.is_none() || code == Some(0))
            }
            Err(e) => {
                eprintln!("[dev] deleteAppId lỗi: {}", e);
                Ok(false)
            }
        }
    }

    /// Tải Team Provisioning Profile.
    pub fn download_team_provisioning_profile(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
    ) -> Result<Profile> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thiếu app_id_id", app_id.identifier))?;

        let delays = [3u64, 5, 7];
        let mut last_err: Option<anyhow::Error> = None;

        for (attempt, delay) in delays.iter().enumerate() {
            let mut params = HashMap::new();
            params.insert("appIdId".into(), Value::String(app_id_id.clone()));

            match self.request_plist(
                auth,
                "ios/downloadTeamProvisioningProfile.action",
                params,
                true,
            ) {
                Ok(resp) => {
                    if let Some(profile) = resp
                        .get("provisioningProfile")
                        .and_then(|v| v.as_dictionary())
                    {
                        let encoded = profile
                            .get("encodedProfile")
                            .or_else(|| profile.get("content"))
                            .or_else(|| profile.get("profileContent"))
                            .and_then(|v| v.as_data())
                            .ok_or_else(|| anyhow!("Profile thiếu 'encodedProfile'"))?;

                        return Ok(Profile {
                            encoded_profile: encoded.to_vec(),
                        });
                    }

                    last_err = Some(anyhow!(
                        "Response thiếu provisioningProfile: resultCode={:?}, userString={:?}",
                        resp.get("resultCode")
                            .and_then(|v| v.as_signed_integer()),
                        resp.get("userString")
                            .or_else(|| resp.get("resultString"))
                            .and_then(|v| v.as_string())
                    ));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }

            if attempt + 1 < delays.len() {
                println!(
                    "[dev] Profile fail (attempt {}/{}), retry sau {}s",
                    attempt + 1,
                    delays.len(),
                    delay
                );
                std::thread::sleep(std::time::Duration::from_secs(*delay));
            }
        }

        Err(last_err
            .unwrap_or_else(|| anyhow!("download profile thất bại sau {} lần", delays.len())))
    }

    /// Đăng ký nhiều bundle một lúc.
    pub fn register_bundles(
        &mut self,
        auth: &mut AnisetteClient,
        bundles: &[(String, String)],
    ) -> Result<Vec<AppId>> {
        let existing = self.list_app_ids_full(auth)?;
        let mut out = Vec::new();

        for (bundle_id, name) in bundles {
            if let Some(a) = existing.iter().find(|a| a.identifier == *bundle_id) {
                println!("[dev] App ID đã có: {}", bundle_id);
                out.push(a.clone());
                continue;
            }

            println!("[dev] Tạo App ID: {}", bundle_id);
            let app_id = self.create_app_id_full(auth, bundle_id, name)?;
            out.push(app_id);
        }

        Ok(out)
    }
}

// ============================================================
//  APP GROUP APIs
// ============================================================

impl DeveloperClient {
    /// List App Groups hiện có.
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

    /// Tạo App Group.
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

    /// Đảm bảo App Group tồn tại.
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

    /// Gán App Group vào App ID.
    pub fn assign_app_group(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
        group_id: &str,
    ) -> Result<()> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thiếu app_id_id", app_id.identifier))?;

        let mut params = HashMap::new();
        params.insert("appIdId".into(), Value::String(app_id_id.clone()));
        params.insert(
            "appGroups".into(),
            Value::Array(vec![Value::String(group_id.to_string())]),
        );

        let resp = self
            .request_plist(
                auth,
                "ios/assignAppGroupsToAppId.action",
                params,
                true,
            )
            .context("assignAppGroupsToAppId thất bại")?;

        let result_code = resp
            .get("resultCode")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(0);

        if result_code != 0 {
            return Err(anyhow!(
                "assign App Group thất bại: code={} userString={:?}",
                result_code,
                resp.get("userString").and_then(|v| v.as_string())
            ));
        }

        println!(
            "[dev] ✅ Gán App Group {} vào {}",
            group_id, app_id.identifier
        );
        Ok(())
    }

    /// Bật Increased Memory Limit cho App ID.
    pub fn add_increased_memory_limit(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
    ) -> Result<()> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thiếu app_id_id", app_id.identifier))?;

        let mut params = HashMap::new();
        params.insert("appIdId".into(), Value::String(app_id_id.clone()));
        params.insert(
            "features".into(),
            Value::Array(vec![Value::String(
                "INCREASED_MEMORY_LIMIT".to_string(),
            )]),
        );

        let resp = self
            .request_plist(auth, "ios/enableAppIdFeature.action", params, true)
            .context("enableAppIdFeature thất bại")?;

        let result_code = resp
            .get("resultCode")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(0);

        if result_code != 0 {
            return Err(anyhow!(
                "enable IncreasedMemoryLimit thất bại: code={} userString={:?}",
                result_code,
                resp.get("userString").and_then(|v| v.as_string())
            ));
        }

        println!(
            "[dev] ✅ Bật Increased Memory Limit cho {}",
            app_id.identifier
        );
        Ok(())
    }
}
