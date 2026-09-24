// src/dev/teams.rs
use anyhow::Result;
use plist::{Dictionary, Value};
use std::collections::HashMap;

use super::client::DeveloperClient;
use crate::auth::AnisetteClient;

impl DeveloperClient {
    pub fn list_teams(&mut self, auth: &mut AnisetteClient) -> Result<Vec<Dictionary>> {
        let resp = self.request_plist(auth, "listTeams.action", HashMap::new(), false)?;
        
        let teams_arr = match resp.get("teams").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => return Ok(Vec::new()),
        };

        let mut result = Vec::new();
        for team in teams_arr {
            if let Value::Dictionary(d) = team {
                result.push(d.clone());
            }
        }
        Ok(result)
    }
}
