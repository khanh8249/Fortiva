pub mod cert_manager;
pub mod device_manager;
pub mod sidestore_pairing;
pub mod validate;   // ← THÊM

pub use sidestore_pairing::{list_pairing_records, setup_sidestore_pairing};
