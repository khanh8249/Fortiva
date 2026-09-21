// src/dev/plist_api.rs
use anyhow::{anyhow, Result};
use plist::{Dictionary, Value};
use std::collections::HashMap;

use super::client::DeveloperClient;
use super::DevError;
use crate::auth::AnisetteClient;

impl DeveloperClient {
    pub fn list_teams(&mut self, auth: &mut AnisetteClient) -> Result<Vec<Dictionary>> {
        let resp = self.request_plist(auth, "listTeams.action", HashMap::new(), false)?;
        Ok(extract_array_of_dicts(&resp, "teams"))
    }

    pub fn list_devices(&mut self, auth: &mut AnisetteClient) -> Result<Vec<Dictionary>> {
        let resp = self.request_plist(auth, "ios/listDevices.action", HashMap::new(), true)?;
        Ok(extract_array_of_dicts(&resp, "devices"))
    }

    pub fn register_device(
        &mut self,
        auth: &mut AnisetteClient,
        device_name: &str,
        device_udid: &str,
    ) -> Result<Option<Dictionary>> {
        self.last_error = None;

        let mut params = HashMap::new();
        params.insert("deviceNumber".into(), Value::String(device_udid.into()));
        params.insert("name".into(), Value::String(device_name.into()));

        let resp = self.request_plist(auth, "ios/addDevice.action", params, true)?;

        if let Some(device) = resp.get("device").and_then(|v| v.as_dictionary()) {
            return Ok(Some(device.clone()));
        }

        self.last_error = Some(DevError {
            result_code: resp
                .get("resultCode")
                .and_then(|v| v.as_signed_integer()),
            user_string: extract_string(&resp, &["userString", "resultString"]),
        });
        Ok(None)
    }

    pub fn list_app_ids(&mut self, auth: &mut AnisetteClient) -> Result<Vec<Dictionary>> {
        let resp = self.request_plist(auth, "ios/listAppIds.action", HashMap::new(), true)?;
        Ok(extract_array_of_dicts(&resp, "appIds"))
    }

    pub fn create_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        bundle_id: &str,
        name: &str,
    ) -> Result<Option<Dictionary>> {
        self.last_error = None;

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
        params.insert("identifier".into(), Value::String(bundle_id.into()));
        params.insert("name".into(), Value::String(sanitized));

        let resp = self.request_plist(auth, "ios/addAppId.action", params, true)?;

        if let Some(app_id) = resp.get("appId").and_then(|v| v.as_dictionary()) {
            return Ok(Some(app_id.clone()));
        }

        self.last_error = Some(DevError {
            result_code: resp
                .get("resultCode")
                .and_then(|v| v.as_signed_integer()),
            user_string: extract_string(&resp, &["userString", "resultString"]),
        });
        Ok(None)
    }

    pub fn delete_app_id(
        &mut self,
        auth: &mut AnisetteClient,
        app_id_id: &str,
    ) -> Result<bool> {
        let mut params = HashMap::new();
        params.insert("appIdId".into(), Value::String(app_id_id.into()));

        match self.request_plist(auth, "ios/deleteAppId.action", params, true) {
            Ok(resp) => {
                let code = resp
                    .get("resultCode")
                    .and_then(|v| v.as_signed_integer());
                Ok(code.is_none() || code == Some(0))
            }
            Err(_) => Ok(false),
        }
    }

    pub fn download_provisioning_profile(
        &mut self,
        auth: &mut AnisetteClient,
        app_id_id: &str,
    ) -> Result<Option<Dictionary>> {
        let delays = [3u64, 5, 7]; // backoff
        self.last_error = None;

        for (attempt, delay) in delays.iter().enumerate() {
            let mut params = HashMap::new();
            params.insert("appIdId".into(), Value::String(app_id_id.into()));

            match self.request_plist(
                auth,
                "ios/downloadTeamProvisioningProfile.action",
                params,
                true,
            ) {
                Ok(resp) => {
                    if let Some(profile) = resp.get("provisioningProfile") {
                        return Ok(Some(profile.as_dictionary().cloned().unwrap_or_default()));
                    }

                    self.last_error = Some(DevError {
                        result_code: resp
                            .get("resultCode")
                            .and_then(|v| v.as_signed_integer()),
                        user_string: extract_string(&resp, &["userString", "resultString"]),
                    });
                    eprintln!(
                        "[DevAPI] Profile fail (attempt {}/{}): {:?}",
                        attempt + 1,
                        delays.len(),
                        self.last_error
                    );
                }
                Err(e) => {
                    self.last_error = Some(DevError {
                        result_code: Some(-1),
                        user_string: e.to_string(),
                    });
                    eprintln!("[DevAPI] Profile err: {}", e);
                }
            }

            if attempt + 1 < delays.len() {
                std::thread::sleep(std::time::Duration::from_secs(*delay));
            }
        }

        Ok(None)
    }
}

// ============ HELPERS ============

fn extract_array_of_dicts(dict: &Dictionary, key: &str) -> Vec<Dictionary> {
    dict.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_dictionary().cloned())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_string(dict: &Dictionary, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = dict.get(*k).and_then(|v| v.as_string()) {
            return s.to_string();
        }
    }
    String::new()
}