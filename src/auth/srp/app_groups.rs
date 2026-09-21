// src/dev/app_groups.rs - STUB
use anyhow::{anyhow, Result};

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

impl DeveloperClient {
    pub fn list_app_groups(
        &mut: &mut AnisetteClient,
    ) -> Result<Vec<String>> {
        Err(anyhow!("list_app_groups chưa implement"))
    }
}