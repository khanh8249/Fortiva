// src/sideload/bundle.rs
use anyhow::{anyhow, Context, Result};
use plist::{Dictionary, Value};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Bundle {
    pub app_info: Dictionary,
    pub bundle_dir: PathBuf,

    app_extensions: Vec<Bundle>,
    frameworks: Vec<Bundle>,
    libraries: Vec<String>,
}

impl Bundle {
    pub fn new(bundle_dir: PathBuf) -> Result<Self> {
        let mut bundle_path = bundle_dir;

        // Bỏ trailing slash
        if let Some(s) = bundle_path.to_str() {
            if s.ends_with('/') || s.ends_with('\\') {
                bundle_path = PathBuf::from(&s[..s.len() - 1]);
            }
        }

        let info_plist_path = bundle_path.join("Info.plist");
        if !info_plist_path.exists() {
            return Err(anyhow!(
                "Không có Info.plist: {}",
                info_plist_path.display()
            ));
        }

        let plist_data = fs::read(&info_plist_path)
            .with_context(|| format!("Đọc Info.plist thất bại: {}", info_plist_path.display()))?;

        let app_info: Dictionary = plist::from_bytes(&plist_data)
            .with_context(|| format!("Parse Info.plist thất bại: {}", info_plist_path.display()))?;

        // Đọc extensions từ PlugIns/
        let plug_ins_dir = bundle_path.join("PlugIns");
        let app_extensions = if plug_ins_dir.is_dir() {
            read_sub_bundles(&plug_ins_dir)?
        } else {
            Vec::new()
        };

        // Đọc frameworks từ Frameworks/
        let frameworks_dir = bundle_path.join("Frameworks");
        let frameworks = if frameworks_dir.is_dir() {
            read_sub_bundles(&frameworks_dir)?
        } else {
            Vec::new()
        };

        // Tìm .dylib đệ quy
        let libraries = find_dylibs(&bundle_path, &bundle_path)?;

        Ok(Bundle {
            app_info,
            bundle_dir: bundle_path,
            app_extensions,
            frameworks,
            libraries,
        })
    }

    pub fn set_bundle_identifier(&mut self, id: &str) {
        self.app_info.insert(
            "CFBundleIdentifier".to_string(),
            Value::String(id.to_string()),
        );
    }

    pub fn bundle_identifier(&self) -> Option<&str> {
        self.app_info
            .get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
    }

    pub fn bundle_name(&self) -> Option<&str> {
        self.app_info
            .get("CFBundleName")
            .and_then(|v| v.as_string())
            .or_else(|| {
                self.app_info
                    .get("CFBundleDisplayName")
                    .and_then(|v| v.as_string())
            })
    }

    pub fn app_extensions(&self) -> &[Bundle] {
        &self.app_extensions
    }

    pub fn app_extensions_mut(&mut self) -> &mut [Bundle] {
        &mut self.app_extensions
    }

    pub fn frameworks(&self) -> &[Bundle] {
        &self.frameworks
    }

    pub fn frameworks_mut(&mut self) -> &mut [Bundle] {
        &mut self.frameworks
    }

    /// Ghi lại Info.plist dạng binary.
    pub fn write_info(&self) -> Result<()> {
        let info_plist_path = self.bundle_dir.join("Info.plist");
        let file = File::create(&info_plist_path)
            .with_context(|| format!("Tạo Info.plist thất bại: {}", info_plist_path.display()))?;

        let mut writer = BufWriter::new(file);
        plist::to_writer_binary(&mut writer, &self.app_info)
            .with_context(|| format!("Ghi Info.plist thất bại: {}", info_plist_path.display()))?;

        Ok(())
    }

    /// Thu thập tất cả bundle con (đệ quy).
    fn collect_nested_into(&self, out: &mut Vec<Bundle>) {
        for ext in &self.app_extensions {
            out.push(ext.clone());
            ext.collect_nested_into(out);
        }
        for fw in &self.frameworks {
            out.push(fw.clone());
            fw.collect_nested_into(out);
        }
    }

    /// Trả về tất cả bundle (kể cả bản thân), sắp xếp sâu nhất trước.
    pub fn collect_bundles_sorted(&self) -> Vec<Bundle> {
        let mut bundles = Vec::new();
        self.collect_nested_into(&mut bundles);

        // Thêm bundle từ dylib
        for lib in &self.libraries {
            bundles.push(Bundle::from_dylib_path(self.bundle_dir.join(lib)));
        }

        bundles.push(self.clone());

        // Sắp xếp theo độ sâu đường dẫn, sâu nhất trước
        bundles.sort_by_key(|b| std::cmp::Reverse(b.bundle_dir.components().count()));

        bundles
    }

    fn from_dylib_path(path: PathBuf) -> Self {
        Self {
            app_info: Dictionary::new(),
            bundle_dir: path,
            app_extensions: Vec::new(),
            frameworks: Vec::new(),
            libraries: Vec::new(),
        }
    }
}

/// Đọc tất cả sub-bundle từ một thư mục.
fn read_sub_bundles(dir: &Path) -> Result<Vec<Bundle>> {
    let mut out = Vec::new();

    for entry in fs::read_dir(dir)
        .with_context(|| format!("Đọc thư mục thất bại: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        // Chỉ lấy .appex, .framework, .bundle
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let is_bundle = name.ends_with(".appex")
            || name.ends_with(".framework")
            || name.ends_with(".bundle");

        if !is_bundle {
            continue;
        }

        if !path.join("Info.plist").exists() {
            continue;
        }

        match Bundle::new(path) {
            Ok(b) => out.push(b),
            Err(e) => {
                eprintln!("[bundle] Bỏ qua {}: {}", name, e);
            }
        }
    }

    Ok(out)
}

/// Tìm tất cả file .dylib (đệ quy).
fn find_dylibs(dir: &Path, root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_dylibs(dir, root, &mut out)?;
    Ok(out)
}

fn collect_dylibs(dir: &Path, root: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("Đọc thư mục thất bại: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".dylib") {
                    if let Ok(rel) = path.strip_prefix(root) {
                        out.push(rel.to_string_lossy().to_string());
                    }
                }
            }
        } else if path.is_dir() {
            // Bỏ qua thư mục bundle con (đã xử lý riêng)
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".appex")
                || name.ends_with(".framework")
                || name.ends_with(".bundle")
            {
                continue;
            }
            collect_dylibs(&path, root, out)?;
        }
    }

    Ok(())
}