// src/cache/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::session::Session;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnisetteCache {
    pub headers: HashMap<String, String>,
    pub server_url: String,
    pub fetched_at: u64,
    #[serde(default)]
    pub never_expires: bool,
}

impl AnisetteCache {
    pub fn path() -> Result<PathBuf> {
        Ok(Session::dir()?.join("anisette.json"))
    }

    pub fn load() -> Result<Option<Self>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        let cache: Self = serde_json::from_str(&content)
            .context("Parse anisette.json fail")?;
        Ok(Some(cache))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Lưu vĩnh viễn — không bao giờ expire.
    pub fn is_expired(&self) -> bool {
        false
    }

    pub fn age_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.fetched_at)
    }

    pub fn save_from(headers: HashMap<String, String>, server_url: String) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cache = Self {
            headers,
            server_url,
            fetched_at: now,
            never_expires: true,
        };
        cache.save()
    }
}
