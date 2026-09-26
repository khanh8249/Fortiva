//! CodeResources builder — hash toàn bộ file trong bundle.

use anyhow::{Context, Result};
use plist::{Dictionary, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const CS_EXCLUDE: &[&str] = &[
    "_CodeSignature",
    "CodeResources",
    "embedded.mobileprovision",
    "SC_Info",
    ".DS_Store",
    "PkgInfo",
];

pub fn build(bundle_dir: &Path, is_main: bool) -> Result<Vec<u8>> {
    let mut files = Dictionary::new();
    let mut files2 = Dictionary::new();

    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(bundle_dir).min_depth(1) {
        let entry = entry.context("WalkDir entry fail")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(bundle_dir)
            .context("Strip prefix fail")?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        let mut skip = false;
        for excl in CS_EXCLUDE {
            if rel_str == *excl
                || rel_str.starts_with(&format!("{}/", excl))
            {
                skip = true;
                break;
            }
        }
        if skip {
            continue;
        }
        if is_main && rel_str == "Info.plist" {
            continue;
        }
        entries.push(entry.path().to_path_buf());
    }

    entries.sort();

    for path in &entries {
        let rel = path.strip_prefix(bundle_dir)?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        let data = fs::read(path)
            .with_context(|| format!("Read {}", path.display()))?;

        let sha1_hash = {
            let mut h = Sha1::new();
            h.update(&data);
            h.finalize().to_vec()
        };
        let sha256_hash = {
            let mut h = Sha256::new();
            h.update(&data);
            h.finalize().to_vec()
        };

        files.insert(rel_str.clone(), Value::Data(sha1_hash));

        let mut entry2 = Dictionary::new();
        entry2.insert("hash".into(), Value::Data(sha256_hash.clone()));
        entry2.insert("hash2".into(), Value::Data(sha256_hash));
        files2.insert(rel_str, Value::Dictionary(entry2));
    }

    let mut root = Dictionary::new();
    root.insert("files".into(), Value::Dictionary(files));
    root.insert("files2".into(), Value::Dictionary(files2));

    let default_rule = {
        let mut d = Dictionary::new();
        d.insert("weight".into(), Value::Integer(10.into()));
        Value::Dictionary(d)
    };
    let nested_rule = {
        let mut d = Dictionary::new();
        d.insert("nested".into(), Value::Boolean(true));
        d.insert("weight".into(), Value::Integer(1000.into()));
        Value::Dictionary(d)
    };

    let mut rules = Dictionary::new();
    rules.insert("^.*".into(), default_rule.clone());

    let mut rules2 = Dictionary::new();
    rules2.insert("^.*".into(), default_rule);
    rules2.insert("^.*\\.lproj/".into(), nested_rule.clone());
    rules2.insert("^.*\\.lproj/locversion.plist$".into(), nested_rule);

    root.insert("rules".into(), Value::Dictionary(rules));
    root.insert("rules2".into(), Value::Dictionary(rules2));

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(root))
        .context("Serialize CodeResources XML fail")?;

    Ok(buf)
}
