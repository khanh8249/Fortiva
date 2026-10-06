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

impl DeveloperClient {
    pub fn list_app_ids_full(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<AppId>> {
        let resp = self
            .request_plist(auth, "ios/listAppIds.action", HashMap::new(), true)
            .context("listAppIds that bai")?;

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
            .context("addAppId that bai")?;

        let app_id = resp
            .get("appId")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| {
                let err = DevError {
                    result_code: resp.get("resultCode").and_then(plist_integer),
                    user_string: resp
                        .get("userString")
                        .or_else(|| resp.get("resultString"))
                        .and_then(|v| v.as_string())
                        .unwrap_or("?")
                        .to_string(),
                };
                anyhow!("addAppId that bai: {:?}", err)
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

    pub fn ensure_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        bundle_id: &str,
        name: &str,
    ) -> Result<AppId> {
        let existing = self.list_app_ids_full(auth)?;
        if let Some(a) = existing.iter().find(|a| a.identifier == bundle_id) {
            println!("[dev] App ID da co: {}", bundle_id);
            return Ok(a.clone());
        }

        println!("[dev] Tao App ID: {}", bundle_id);
        self.create_app_id_full(auth, bundle_id, name)
    }

    pub fn delete_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        app_id_id: &str,
    ) -> Result<bool> {
        let mut params = HashMap::new();
        params.insert("appIdId".into(), Value::String(app_id_id.to_string()));

        match self.request_plist(auth, "ios/deleteAppId.action", params, true) {
            Ok(resp) => {
                let code = resp.get("resultCode").and_then(plist_integer);
                Ok(code.is_none() || code == Some(0))
            }
            Err(e) => {
                eprintln!("[dev] deleteAppId loi: {}", e);
                Ok(false)
            }
        }
    }

    pub fn download_team_provisioning_profile(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
    ) -> Result<Profile> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thieu app_id_id", app_id.identifier))?;

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
                            .ok_or_else(|| anyhow!("Profile thieu 'encodedProfile'"))?;

                        return Ok(Profile {
                            encoded_profile: encoded.to_vec(),
                        });
                    }

                    last_err = Some(anyhow!(
                        "Response thieu provisioningProfile: resultCode={:?}, userString={:?}",
                        resp.get("resultCode").and_then(plist_integer),
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
            .unwrap_or_else(|| anyhow!("download profile that bai sau {} lan", delays.len())))
    }

    pub fn register_bundles(
        &mut self,
        auth: &mut AnisetteClient,
        bundles: &[(String, String)],
    ) -> Result<Vec<AppId>> {
        let existing = self.list_app_ids_full(auth)?;
        let mut out = Vec::new();

        for (bundle_id, name) in bundles {
            if let Some(a) = existing.iter().find(|a| a.identifier == *bundle_id) {
                println!("[dev] App ID da co: {}", bundle_id);
                out.push(a.clone());
                continue;
            }

            println!("[dev] Tao App ID: {}", bundle_id);
            let app_id = self.create_app_id_full(auth, bundle_id, name)?;
            out.push(app_id);
        }

        Ok(out)
    }

    pub fn assign_app_group(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
        group_id: &str,
    ) -> Result<()> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thieu app_id_id", app_id.identifier))?;

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
            .context("assignAppGroupsToAppId that bai")?;

        let result_code = resp.get("resultCode").and_then(plist_integer).unwrap_or(0);

        if result_code != 0 {
            return Err(anyhow!(
                "assign App Group that bai: code={} userString={:?}",
                result_code,
                resp.get("userString").and_then(|v| v.as_string())
            ));
        }

        println!(
            "[dev] Gan App Group {} vao {}",
            group_id, app_id.identifier
        );
        Ok(())
    }

    pub fn add_increased_memory_limit(
        &mut self,
        auth: &mut AnisetteClient,
        app_id: &AppId,
    ) -> Result<()> {
        let app_id_id = app_id
            .app_id_id
            .as_ref()
            .ok_or_else(|| anyhow!("App ID {} thieu app_id_id", app_id.identifier))?;

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
            .context("enableAppIdFeature that bai")?;

        let result_code = resp.get("resultCode").and_then(plist_integer).unwrap_or(0);

        if result_code != 0 {
            return Err(anyhow!(
                "enable IncreasedMemoryLimit that bai: code={} userString={:?}",
                result_code,
                resp.get("userString").and_then(|v| v.as_string())
            ));
        }

        println!(
            "[dev] Bat Increased Memory Limit cho {}",
            app_id.identifier
        );
        Ok(())
    }
}

fn plist_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i.to_string().parse::<i64>().ok(),
        Value::Real(r) => Some(*r as i64),
        _ => None,
    }
}
