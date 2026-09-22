// src/dev/mod.rs
mod app_ids;
mod certificate;
mod client;
mod devices;
mod json_api;
mod plist_api;
mod teams;

pub use app_ids::{AppId, Profile};
pub use certificate::{decode_cert_content, CertificateBundle};
pub use client::{
    DevError, DeveloperClient, BASE_URL_QH65B2, BASE_URL_V1, CLIENT_ID, PROTOCOL_VERSION,
    XCODE_VERSION,
};
pub use devices::Device;
pub use teams::DeveloperTeam;