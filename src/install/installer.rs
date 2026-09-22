// src/install/installer.rs
use anyhow::Result;
use idevice::services::installation_proxy::InstallationProxyClient;
use plist::{Dictionary, Value};

pub async fn install_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: Dictionary,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |_| async {},
            (),
        )
        .await?;

    Ok(())
}

pub async fn upgrade_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: Dictionary,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |_| async {},
            (),
        )
        .await?;

    Ok(())
}
