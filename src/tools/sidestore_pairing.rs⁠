use anyhow::Result;
use idevice::{
    services::{
        afc::AfcClient, house_arrest::HouseArrestClient,
        installation_proxy::InstallationProxyClient, lockdown::LockdownClient,
    },
    Idevice, IdeviceService,
};

pub async fn pairing_file_info(pairing: &[u8]) {
    println!("[sidestore] Pairing file: {} bytes", pairing.len());
}

pub async fn get_pairing_xml(device: &Idevice) -> Result<Vec<u8>> {
    let mut _lockdown = LockdownClient::connect(device).await?;
    let xml = vec![];
    Ok(xml)
}

pub async fn setup_sidestore(device: &Idevice) -> Result<()> {
    let lockdown = LockdownClient::connect(device).await?;

    let instproxy_service = lockdown
        .start_service("com.apple.mobile.installation_proxy")
        .await?;
    let mut _instproxy = InstallationProxyClient::new(instproxy_service);

    let ha_lockdown = LockdownClient::connect(device).await?;
    let ha_service = ha_lockdown
        .start_service("com.apple.mobile.house_arrest")
        .await?;
    let mut ha = HouseArrestClient::new(ha_service);

    let mut _afc = AfcClient::new(ha.into_inner());

    Ok(())
}
