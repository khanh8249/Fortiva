//! Validate pairing file cho SideStore / StikDebug / Sideloadly.
//!
//! Kiểm tra:
//! - Đủ key bắt buộc
//! - Certificate / private key parse được
//! - UDID khớp với device
//! - WiFiMACAddress không rỗng
//! - Không có key rỗng/bất thường
//! - Cảnh báo cho iOS 17.4+ (cần RPPairing)

use anyhow::{anyhow, Result};
use plist::Value;
use std::path::Path;

/// Kết quả validate chi tiết.
#[derive(Debug)]
pub struct ValidationReport {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
    pub keys_present: Vec<String>,
    pub keys_missing: Vec<String>,
}

impl ValidationReport {
    pub fn print(&self) {
        println!();
        println!("======================================================");
        println!("  Pairing File Validation Report");
        println!("======================================================");
        println!();

        if self.ok {
            println!("  [OK] File hợp lệ");
        } else {
            println!("  [FAIL] File KHÔNG hợp lệ");
        }
        println!();

        if !self.info.is_empty() {
            println!("  Thông tin:");
            for msg in &self.info {
                println!("    [i] {}", msg);
            }
            println!();
        }

        if !self.keys_present.is_empty() {
            println!("  Keys có mặt ({}):", self.keys_present.len());
            for key in &self.keys_present {
                println!("    [OK] {}", key);
            }
            println!();
        }

        if !self.keys_missing.is_empty() {
            println!("  Keys THIẾU ({}):", self.keys_missing.len());
            for key in &self.keys_missing {
                println!("    [!!] {}", key);
            }
            println!();
        }

        if !self.warnings.is_empty() {
            println!("  Cảnh báo ({}):", self.warnings.len());
            for msg in &self.warnings {
                println!("    [!] {}", msg);
            }
            println!();
        }

        if !self.errors.is_empty() {
            println!("  Lỗi ({}):", self.errors.len());
            for msg in &self.errors {
                println!("    [X] {}", msg);
            }
            println!();
        }

        println!("======================================================");
        println!();
    }
}

/// Key bắt buộc cho pairing file Lockdown.
pub const REQUIRED_KEYS: &[&str] = &[
    "DeviceCertificate",
    "HostCertificate",
    "HostPrivateKey",
    "RootCertificate",
    "RootPrivateKey",
    "SystemBUID",
    "HostID",
    "WiFiMACAddress",
    "UDID",
];

/// Key khuyến nghị có (không bắt buộc nhưng SideStore dùng).
pub const OPTIONAL_KEYS: &[&str] = &[
    "EscrowBag",
    "ProductType",
    "ProductVersion",
    "DeviceName",
    "DevicePublicKey",
    "HostPublicKey",
];

/// Validate một file pairing từ bytes.
pub fn validate_bytes(
    data: &[u8],
    expected_udid: Option<&str>,
) -> Result<ValidationReport> {
    let mut report = ValidationReport {
        ok: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        info: Vec::new(),
        keys_present: Vec::new(),
        keys_missing: Vec::new(),
    };

    report.info.push(format!("Kích thước: {} bytes", data.len()));

    // Bước 1: Parse plist
    let val: Value = match plist::from_bytes(data) {
        Ok(v) => v,
        Err(e) => {
            report.ok = false;
            report.errors.push(format!("Không parse được plist: {}", e));
            return Ok(report);
        }
    };

    let dict = match val.as_dictionary() {
        Some(d) => d,
        None => {
            report.ok = false;
            report.errors.push("Root không phải dictionary".to_string());
            return Ok(report);
        }
    };

    report.info.push(format!("Tổng số key: {}", dict.len()));

    // Bước 2: Check các key bắt buộc
    for key in REQUIRED_KEYS {
        if dict.contains_key(*key) {
            report.keys_present.push((*key).to_string());
        } else {
            report.keys_missing.push((*key).to_string());
            report.ok = false;
            report.errors.push(format!("Thiếu key bắt buộc: {}", key));
        }
    }

    // Check optional keys
    for key in OPTIONAL_KEYS {
        if dict.contains_key(*key) {
            report.keys_present.push(format!("{} (tùy chọn)", key));
        } else {
            report
                .warnings
                .push(format!("Thiếu key tùy chọn: {} (không bắt buộc)", key));
        }
    }

    // Nếu thiếu key bắt buộc thì return sớm
    if !report.ok {
        return Ok(report);
    }

    // Bước 3: Validate từng field quan trọng
    validate_string_field(dict, "UDID", &mut report, true);
    validate_string_field(dict, "SystemBUID", &mut report, false);
    validate_string_field(dict, "HostID", &mut report, false);
    validate_string_field(dict, "WiFiMACAddress", &mut report, true);

    // Bước 4: Validate UDID khớp device (nếu có expected)
    if let Some(expected) = expected_udid {
        if let Some(udid_val) = dict.get("UDID").and_then(|v| v.as_string()) {
            if udid_val != expected {
                report.ok = false;
                report.errors.push(format!(
                    "UDID không khớp: file có '{}' nhưng device là '{}'",
                    udid_val, expected
                ));
            } else {
                report.info.push(format!("UDID khớp device: {}", udid_val));
            }
        }
    }

    // Bước 5: Validate data blob (certificates + keys)
    validate_data_field(dict, "DeviceCertificate", &mut report);
    validate_data_field(dict, "HostCertificate", &mut report);
    validate_data_field(dict, "HostPrivateKey", &mut report);
    validate_data_field(dict, "RootCertificate", &mut report);
    validate_data_field(dict, "RootPrivateKey", &mut report);

    // Bước 6: Validate định dạng WiFiMACAddress
    if let Some(mac) = dict.get("WiFiMACAddress").and_then(|v| v.as_string()) {
        if !is_valid_mac(mac) {
            report
                .warnings
                .push(format!("WiFiMACAddress format bất thường: {}", mac));
        }
    }

    // Bước 7: Check EscrowBag rỗng
    if let Some(escrow) = dict.get("EscrowBag") {
        if escrow.as_data().map(|d| d.is_empty()).unwrap_or(true) {
            report
                .warnings
                .push("EscrowBag tồn tại nhưng rỗng".to_string());
        }
    }

    Ok(report)
}

/// Validate file pairing từ path.
pub fn validate_file(path: &Path, expected_udid: Option<&str>) -> Result<ValidationReport> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow!("Không đọc được file {}: {}", path.display(), e))?;

    let mut report = validate_bytes(&data, expected_udid)?;
    report.info.insert(0, format!("File: {}", path.display()));
    Ok(report)
}

/// Validate 1 string field.
fn validate_string_field(
    dict: &plist::Dictionary,
    key: &str,
    report: &mut ValidationReport,
    required_non_empty: bool,
) {
    match dict.get(key).and_then(|v| v.as_string()) {
        Some(s) => {
            if s.is_empty() {
                if required_non_empty {
                    report.ok = false;
                    report.errors.push(format!("Field '{}' rỗng", key));
                } else {
                    report
                        .warnings
                        .push(format!("Field '{}' rỗng (không bắt buộc)", key));
                }
            } else {
                report.info.push(format!("{} = {}", key, s));
            }
        }
        None => {
            if required_non_empty {
                report.ok = false;
                report
                    .errors
                    .push(format!("Field '{}' không phải string", key));
            } else {
                report
                    .warnings
                    .push(format!("Field '{}' không phải string", key));
            }
        }
    }
}

/// Validate 1 data field.
fn validate_data_field(dict: &plist::Dictionary, key: &str, report: &mut ValidationReport) {
    match dict.get(key).and_then(|v| v.as_data()) {
        Some(data) => {
            if data.is_empty() {
                report.ok = false;
                report
                    .errors
                    .push(format!("Field '{}' rỗng (data blob)", key));
            } else {
                report.info.push(format!("{} = {} bytes", key, data.len()));
            }
        }
        None => {
            report.ok = false;
            report
                .errors
                .push(format!("Field '{}' không phải data blob", key));
        }
    }
}

/// Check MAC address format (XX:XX:XX:XX:XX:XX).
fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

/// Cảnh báo nếu iOS version cần RPPairing.
pub fn warn_if_needs_rppairing(ios_version: &str, report: &mut ValidationReport) {
    let mut parts = ios_version.split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    if major > 17 || (major == 17 && minor >= 4) {
        report.warnings.push(format!(
            "iOS {}.{} cần RPPairing record, không phải Lockdown pairing. \
             File Lockdown này có thể bị SideStore từ chối khi cài IPA.",
            major, minor
        ));
    }
}
