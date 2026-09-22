use anyhow::Result;
use idevice::services::installation_proxy::InstallationProxyClient;
use plist::Value;
use std::collections::BTreeMap;

pub async fn install_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: BTreeMap<String, Value>,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options.clone())),
            |_| std::future::ready(()),
        )
        .await?;

    Ok(())
}

pub async fn upgrade_app(
    instproxy: &mut InstallationProxyClient,
    remote_dir: &str,
    options: BTreeMap<String, Value>,
) -> Result<()> {
    instproxy
        .install_with_callback(
            remote_dir,
            Some(Value::Dictionary(options)),
            |_| std::future::ready(()),
        )
        .await?;

    Ok(())
}
