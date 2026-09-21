// src/install/mod.rs
mod afc;
mod afc_rsd;
mod device;
mod installer;

pub use device::{detect_device, DeviceInfo};
pub use installer::{install_app, install_app_rsd};