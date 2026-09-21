// src/dev/teams.rs
use anyhow::{anyhow, Context, Result};
use plist::Value;
use std::collections::HashMap;

use super::client::DeveloperClient;
use crate::auth::anisette::AnisetteClient;

#[derive(Debug, Clone)]
pub struct DeveloperTeam {
    pub team_id: String,
    pub name: String,
    pub team_type: Option<String>,
}

impl DeveloperClient {
    /// Lấy danh sách team.
    pub fn list_teams_full(
        &mut self,
        auth: &mut AnisetteClient,
    ) -> Result<Vec<DeveloperTeam>> {
        let resp = self
            .request_plist(auth, "listTeams.action", HashMap::new(), false)
            .context("listTeams thất bại")?;

        let teams = resp
            .get("teams")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Response không có 'teams'"))?;

        let mut out = Vec::new();
        for t in teams {
            let dict = t
                .as_dictionary()
                .ok_or_else(|| anyhow!("Team không phải dict"))?;

            let team_id = dict
                .get("teamId")
                .or_else(|| dict.get("teamID"))
                .or_else(|| dict.get("id"))
                .and_then(|v| v.as_string())
                .ok_or_else(|| anyhow!("Team thiếu teamId"))?
                .to_string();

            let name = dict
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("(unknown)")
                .to_string();

            let team_type = dict
                .get("type")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            out.push(DeveloperTeam {
                team_id,
                name,
                team_type,
            });
        }

        Ok(out)
    }
}