// src/dev/devices.rs
use anyhow::{anyhow, Context, Result};
use plist::Value;
use std::collections::HashMap;

use super::client::{DeveloperClient, DevError};
use crate::auth::anisette::AnisetteClient;

#[derive(Debug, Clone)]
pub struct Device {
    pub udid: String,
    pub name: String,
}

impl DeveloperClient {
    /// Lấy danh sách device đã đăng ký.
    pub fn list_devices_full(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<Device>> {
        let resp = self
            .request_plist(auth, "ios/listDevices.action", HashMap::new(), true)
            .context("listDevices thất bại")?;

        let devices = resp
            .get("devices")
            .and_then(|v| v.as_array())
            .map(|arr| arr.to_vec())
            .unwrap_or_default();

        let mut out = Vec::new();
        for d in devices {
            let dict = match d.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            let udid = dict
                .get("deviceNumber")
                .or_else(|| dict.get("udid"))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();

            let name = dict
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("(unknown)")
                .to_string();

            if !udid.is_empty() {
                out.push(Device { udid, name });
            }
        }

        Ok(out)
    }

    /// Đảm bảo device đã đăng ký. Nếu chưa → tự đăng ký.
    pub fn ensure_device_registered(
        &mut self,
        auth: &mut AnisetteClient,
        name: &str,
        udid: &str,
    ) -> Result<Device> {
        // Kiểm tra đã có chưa
        let existing = self.list_devices_full(auth)?;
        if let Some(d) = existing.iter().find(|d| d.udid == udid) {
            println!("[dev] Device đã đăng ký: {}", d.name);
            return Ok(d.clone());
        }

        println!("[dev] Device chưa đăng ký, đang đăng ký: {}", udid);

        let mut params = HashMap::new();
        params.insert("deviceNumber".into(), Value::String(udid.to_string()));
        params.insert("name".into(), Value::String(name.to_string()));

        let resp = self
            .request_plist(auth, "ios/addDevice.action", params, true)
            .context("addDevice thất bại")?;

        let device = resp
            .get("device")
            .and_then(|v| v.as_dictionary())
            .ok_or_else(|| {
                let err = DevError {
                    result_code: resp
                        .get("resultCode")
                        .and_then(|v| v.as_signed_integer()),
                    user_string: resp
                        .get("userString")
                        .and_then(|v| v.as_string())
                        .unwrap_or("?")
                        .to_string(),
                };
                anyhow!("addDevice thất bại: {:?}", err)
            })?;

        Ok(Device {
            udid: device
                .get("deviceNumber")
                .and_then(|v| v.as_string())
                .unwrap_or(udid)
                .to_string(),
            name: device
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or(name)
                .to_string(),
        })
    }
}