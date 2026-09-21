// src/dev/devices.rs - STUB
use anyhow::{anyhow, Result};
use plist::Dictionary;

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

#[derive(Debug, Clone)]
pub struct Device {
    pub udid: String,
    pub name: String,
}

impl DeveloperClient {
    pub fn ensure_device_registered(
        &mut self,
        _auth: &mut AnisetteClient,
        _name: &str,
        _udid: &str,
    ) -> Result<Device> {
        Err(anyhow!("ensure_device_registered chưa implement"))
    }
}