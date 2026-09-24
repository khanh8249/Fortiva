// src/dev/mod.rs
pub mod teams;

mod app_groups;
mod app_ids;
mod certificate;
mod client;
mod devices;
mod json_api;
mod plist_api;

pub use app_groups::AppGroup;
pub use app_ids::{AppId, Profile};
pub use certificate::{decode_cert_content, CertificateBundle};
pub use client::{
    DevError, DeveloperClient, BASE_URL_QH65B2, BASE_URL_V1, CLIENT_ID, PROTOCOL_VERSION,
    XCODE_VERSION,
};
pub use devices::Device;
