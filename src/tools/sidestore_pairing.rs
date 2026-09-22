use idevice::services::afc::opcode::AfcFopenMode;

// ...

let devices = usbmuxd
    .get_devices()
    .await
    .context("Lấy devices thất bại")?;

// ...

async fn write_pairing_to_bundle(
    provider: &impl IdeviceProvider,
    bundle_id: &str,
    data: &[u8],
) -> Result<()> {
    let ha = HouseArrestClient::connect(provider)
        .await
        .context("House Arrest connect thất bại")?;

    let mut afc: AfcClient = ha
        .vend_container(bundle_id)
        .await
        .with_context(|| format!("VendContainer thất bại: {}", bundle_id))?;

    let remote_path = format!("/Documents/{}", PAIRING_FILE_NAME);

    let mut file = afc
        .open(&remote_path, AfcFopenMode::WrOnly)
        .await
        .with_context(|| format!("Mở file để ghi thất bại: {}", remote_path))?;

    file.write_entire(data)
        .await
        .with_context(|| format!("Ghi file thất bại: {}", remote_path))?;

    file.close()
        .await
        .context("Đóng AFC file thất bại")?;

    println!(
        "[sidestore]   Ghi {} bytes vào {}",
        data.len(),
        remote_path
    );

    Ok(())
}
