// src/sideload/entitlements.rs
use anyhow::{anyhow, Context, Result};
use plist::{Dictionary, Value};

use super::application::SpecialApp;

/// Trích entitlements từ provisioning profile.
pub fn extract_entitlements(
    profile_data: &[u8],
    special: &Option<SpecialApp>,
    team_id: &str,
) -> Result<Dictionary> {
    // Tìm <plist ...> ... </plist> trong CMS wrapper
    let start = find_subsequence(profile_data, b"<plist")
        .ok_or_else(|| anyhow!("Không tìm thấy <plist trong profile"))?;
    let end = rfind_subsequence(profile_data, b"</plist>")
        .ok_or_else(|| anyhow!("Không tìm thấy </plist> trong profile"))?
        + b"</plist>".len();

    let plist_data = &profile_data[start..end];
    let plist: Value = plist::from_bytes(plist_data)
        .context("Parse profile plist thất bại")?;

    let mut entitlements = plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Profile plist không phải dict"))?
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .ok_or_else(|| anyhow!("Profile thiếu Entitlements"))?
        .clone();

    // Special case: LiveContainer / SideStoreLc cần 128 keychain groups
    if matches!(
        special,
        Some(SpecialApp::SideStoreLc) | Some(SpecialApp::LiveContainer)
    ) {
        let mut keychain_groups = vec![Value::String(format!(
            "{}.com.kdt.livecontainer.shared",
            team_id
        ))];

        for i in 1..128 {
            keychain_groups.push(Value::String(format!(
                "{}.com.kdt.livecontainer.shared.{}",
                team_id, i
            )));
        }

        entitlements.insert(
            "keychain-access-groups".to_string(),
            Value::Array(keychain_groups),
        );
    }

    Ok(entitlements)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
}