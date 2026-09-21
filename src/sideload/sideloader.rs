// src/sideload/sideloader.rs
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::application::{Application, SpecialApp};
use super::cert_identity::CertificateIdentity;
use super::signer::sign_app;
use crate::auth::anisette::AnisetteClient;
use crate::dev::DeveloperClient;

pub struct Sideloader {
    pub dev: DeveloperClient,
    pub anisette: AnisetteClient,
    pub work_dir: PathBuf,
    /// Bật Increased Memory Limit cho LiveContainer
    pub increased_memory_limit: bool,
}

impl Sideloader {
    pub fn new(dev: DeveloperClient, anisette: AnisetteClient, work_dir: PathBuf) -> Self {
        Self {
            dev,
            anisette,
            work_dir,
            increased_memory_limit: true, // default bật cho LiveContainer
        }
    }

    /// Sign IPA (không cài).
    pub fn sign_ipa(
        &mut self,
        ipa_path: &Path,
        cert_pem: &Path,
        key_pem: &Path,
        profile_path: &Path,
    ) -> Result<PathBuf> {
        println!("\n[sideload] ═══ Bắt đầu sign ═══");

        // 1. Load cert
        let cert = CertificateIdentity::from_files(cert_pem, key_pem)
            .context("Load cert identity thất bại")?;
        println!("[sideload] Cert serial: {}", cert.serial_number());
        println!("[sideload] Team ID: {}", cert.machine_id);

        // 2. Load profile
        let profile_data = fs::read(profile_path)
            .with_context(|| format!("Đọc profile thất bại: {}", profile_path.display()))?;

        // 3. Parse app
        println!("\n[sideload] Parse IPA...");
        let mut app = Application::new(ipa_path.to_path_buf())?;

        let special = app.get_special_app();
        if let Some(s) = &special {
            println!("[sideload] 🎯 Special app: {}", s);
        }

        // 4. Patch bundle ID
        let main_bundle_id = app.main_bundle_id()?;
        let team_id = cert.machine_id.clone();
        let new_bundle_id = format!("{}.{}", main_bundle_id, team_id);
        let main_app_name = app.main_app_name()?;

        println!(
            "\n[sideload] Patch bundle ID: {} → {}",
            main_bundle_id, new_bundle_id
        );
        app.update_bundle_id(&main_bundle_id, &new_bundle_id)?;

        // 5. Register App IDs (chỉ khi có special app hoặc cần thiết)
        let mut main_app_id = None;
        let mut extension_app_ids: Vec<(String, crate::dev::AppId)> = Vec::new();

        if special.is_some() {
            println!("\n[sideload] Đăng ký App IDs...");

            // Main app
            let main_id = self.dev.ensure_app_id(
                &mut self.anisette,
                &new_bundle_id,
                &main_app_name,
            )?;
            println!("[sideload] Main App ID: {}", main_id.identifier);
            main_app_id = Some(main_id);

            // Extensions
            let ext_bundles: Vec<_> = app
                .bundle
                .app_extensions()
                .iter()
                .filter_map(|ext| {
                    let id = ext.bundle_identifier()?.to_string();
                    let name = ext.bundle_name().unwrap_or("Extension").to_string();
                    Some((id, name))
                })
                .collect();

            for (ext_id, ext_name) in ext_bundles {
                println!("[sideload] Extension: {} ({})", ext_id, ext_name);
                let ext_app_id = self.dev.ensure_app_id(
                    &mut self.anisette,
                    &ext_id,
                    &ext_name,
                )?;
                extension_app_ids.push((ext_id, ext_app_id));
            }
        }

        // 6. Tạo + assign App Group
        let mut group_identifier: Option<String> = None;

        if special.is_some() {
            let grp_id = format!(
                "group.{}",
                if matches!(special, Some(SpecialApp::SideStoreLc)) {
                    format!("com.SideStore.SideStore.{}", team_id)
                } else {
                    new_bundle_id.clone()
                }
            );

            println!("\n[sideload] App Group: {}", grp_id);

            // Tạo App Group
            let app_group = self.dev.ensure_app_group(
                &mut self.anisette,
                &grp_id,
                &main_app_name,
            )?;

            // Assign vào main App ID
            if let Some(ref main_id) = main_app_id {
                self.dev
                    .assign_app_group(&mut self.anisette, main_id, &app_group.group_id)?;
            }

            // Assign vào mỗi extension
            for (_, ext_app_id) in &extension_app_ids {
                self.dev.assign_app_group(
                    &mut self.anisette,
                    ext_app_id,
                    &app_group.group_id,
                )?;
            }

            group_identifier = Some(grp_id);
        }

        // 7. Bật Increased Memory Limit cho LiveContainer
        if self.increased_memory_limit
            && matches!(
                special,
                Some(SpecialApp::LiveContainer) | Some(SpecialApp::SideStoreLc)
            )
        {
            println!("\n[sideload] Bật Increased Memory Limit...");

            if let Some(ref main_id) = main_app_id {
                // Không fail cứng nếu lỗi — một số tài khoản không có feature này
                if let Err(e) = self
                    .dev
                    .add_increased_memory_limit(&mut self.anisette, main_id)
                {
                    eprintln!("[sideload] ⚠️ Không bật được cho main app: {}", e);
                }
            }

            for (_, ext_app_id) in &extension_app_ids {
                if let Err(e) = self
                    .dev
                    .add_increased_memory_limit(&mut self.anisette, ext_app_id)
                {
                    eprintln!(
                        "[sideload] ⚠️ Không bật được cho {}: {}",
                        ext_app_id.identifier, e
                    );
                }
            }
        }

        // 8. Apply special app behavior (inject cert p12, ALTAppGroups)
        if let Some(ref grp_id) = group_identifier {
            app.apply_special_app_behavior(&special, grp_id, &cert)?;
        } else {
            // Không có special app → vẫn gọi để xử lý trường hợp đặc biệt nếu có
            let fallback_grp = format!("group.{}", new_bundle_id);
            app.apply_special_app_behavior(&special, &fallback_grp, &cert)?;
        }

        // 9. Ghi Info.plist
        println!("\n[sideload] Ghi Info.plist cho main + extension + framework...");
        app.write_all_info()?;

        // 10. Nhúng profile
        println!("[sideload] Nhúng provisioning profile...");
        app.write_profiles(&profile_data)?;

        // 11. Ký app
        println!("\n[sideload] ═══ Bắt đầu ký ═══");
        sign_app(&mut app, &cert, &profile_data, &special)?;

        let signed_path = app.bundle.bundle_dir.clone();
        println!(
            "\n[sideload] ✅ Ký xong: {}",
            signed_path.display()
        );

        Ok(signed_path)
    }

    /// Sign + install (dùng cho flow end-to-end).
    pub fn sign_and_install(
        &mut self,
        ipa_path: &Path,
        cert_pem: &Path,
        key_pem: &Path,
        profile_path: &Path,
    ) -> Result<()> {
        let signed_path = self.sign_ipa(ipa_path, cert_pem, key_pem, profile_path)?;

        println!("\n[sideload] Bắt đầu cài đặt...");

        // Detect device
        let device = crate::install::detect_device()?;
        println!("[sideload] Device: {}", device.udid);

        // Runtime async
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Tạo tokio runtime thất bại")?;

        rt.block_on(async {
            use idevice::provider::UsbmuxdProvider;
            use idevice::usbmuxd::UsbmuxdAddr;

            let provider = UsbmuxdProvider::new(UsbmuxdAddr::default())
                .await
                .context("Tạo usbmuxd provider thất bại")?;

            crate::install::install_app(&provider, &signed_path, |pct| {
                print!("\r[sideload] Install: {:3}%", pct);
                use std::io::Write;
                std::io::stdout().flush().ok();
            })
            .await?;

            println!();
            Ok::<_, anyhow::Error>(())
        })?;

        println!("[sideload] ✅ Cài đặt thành công!");
        Ok(())
    }
}