// src/config/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::session::Session;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub anisette: AnisetteConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnisetteConfig {
    pub server_url: String,
}

impl Default for AnisetteConfig {
    fn default() -> Self {
        Self {
            server_url: crate::constants::ANISETTE_URL.to_string(),
        }
    }
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(Session::dir()?.join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            let default = Self::default();
            default.save()?;
            return Ok(default);
        }
        let content = fs::read_to_string(&path).context("Doc config.json fail")?;
        serde_json::from_str(&content).context("Parse config.json fail")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn anisette_url() -> String {
        Self::load()
            .map(|c| c.anisette.server_url)
            .unwrap_or_else(|_| crate::constants::ANISETTE_URL.to_string())
    }

    pub fn set_anisette_url(url: &str) -> Result<()> {
        let mut config = Self::load()?;
        config.anisette.server_url = url.to_string();
        config.save()
    }
}
