// src/install/mod.rs
pub mod afc;
pub mod afc_rsd;
pub mod device;
pub mod installer;

pub use device::detect_device;
pub use installer::install_app;
