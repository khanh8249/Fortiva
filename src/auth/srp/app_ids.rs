// src/dev/app_ids.rs - STUB
use anyhow::{anyhow, Result};
use plist::Dictionary;

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

#[derive(Debug, Clone)]
pub struct AppId {
    pub identifier: String,
    pub app_id_id: Option<String>,
    pub name: String,
}

impl DeveloperClient {
    pub fn ensure_app_group(
        &mut self,
        _auth: &mut AnisetteClient,
        _name: &str,
        _group_id: &str,
    ) -> Result<()> {
        Err(anyhow!("ensure_app_group chưa implement"))
    }

    pub fn assign_app_group(
        &mut self,
        _auth: &mut AnisetteClient,
        _app_id: &AppId,
        _group: &str,
    ) -> Result<()> {
        Err(anyhow!("assign_app_group chưa implement"))
    }

    pub fn add_increased_memory_limit(
        &mut self,
        _auth: &mut AnisetteClient,
        _app_id: &AppId,
    ) -> Result<()> {
        Err(anyhow!("add_increased_memory_limit chưa implement"))
    }
}