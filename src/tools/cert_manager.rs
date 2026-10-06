// src/tools/cert_manager.rs
//
// Quản lý certificate: list, revoke.

use anyhow::{Context, Result};

use crate::auth::anisette::AnisetteClient;
use crate::dev::DeveloperClient;

/// In danh sách certificate.
pub fn list_certs(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
) -> Result<Vec<serde_json::Value>> {
    let certs = dev
        .list_certificates(auth)
        .context("List certificates thất bại")?;

    if certs.is_empty() {
        println!("  ⚠️ Chưa có certificate nào.");
        return Ok(Vec::new());
    }

    println!("  Tìm thấy {} certificate:\n", certs.len());
    println!(
        "  {:<4} {:<40} {:<25} {}",
        "STT", "ID", "Tên", "Hết hạn"
    );
    println!("  {}", "─".repeat(110));

    for (i, cert) in certs.iter().enumerate() {
        let id = cert
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        let attrs = cert
            .get("attributes")
            .and_then(|v| v.as_object());

        let name = attrs
            .and_then(|a| a.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        let exp = attrs
            .and_then(|a| a.get("expirationDate"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        let name_display = if name.len() > 24 {
            format!("{}...", &name[..24])
        } else {
            name.to_string()
        };

        println!(
            "  {:<4} {:<40} {:<25} {}",
            i + 1,
            id,
            name_display,
            exp
        );
    }

    Ok(certs)
}

/// Thu hồi 1 certificate theo ID.
pub fn revoke_cert(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
    cert_id: &str,
) -> Result<()> {
    println!("  Đang thu hồi cert: {}", cert_id);

    let ok = dev
        .revoke_certificate(auth, cert_id)
        .context("Revoke certificate thất bại")?;

    if ok {
        println!("  ✅ Thu hồi thành công: {}", cert_id);
    } else {
        println!("  ❌ Thu hồi thất bại: {}", cert_id);
    }

    Ok(())
}

/// Thu hồi nhiều certificate cùng lúc.
pub fn revoke_many(
    dev: &mut DeveloperClient,
    auth: &mut AnisetteClient,
    cert_ids: &[String],
) -> Result<(usize, usize)> {
    let mut success = 0;
    let mut fail = 0;

    for id in cert_ids {
        match revoke_cert(dev, auth, id) {
            Ok(()) => success += 1,
            Err(e) => {
                println!("  ❌ Lỗi: {} - {}", id, e);
                fail += 1;
            }
        }
    }

    Ok((success, fail))
}
