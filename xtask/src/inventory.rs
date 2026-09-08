use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde_json::{Value, json};

use crate::{Result, git};

fn disposition(path: &str) -> &'static str {
    if path.starts_with("conformance/") {
        "extract independent static fixtures, then retire shadow execution"
    } else if path.starts_with("tests/") {
        "port behavior and negative tests to the responsible Rust crate"
    } else if path.contains("release") || path.contains("deployment") || path.contains("cutover") {
        "consolidate release/install/rollback in Rust CLI and xtask"
    } else if path.contains("validate") || path.contains("record") || path.contains("evidence") {
        "consolidate Rust evidence validation; keep historical records immutable"
    } else {
        "review and port reusable qualification behavior before retirement"
    }
}

fn git_paths(bytes: &[u8]) -> Result<BTreeSet<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            let name = std::str::from_utf8(name)?;
            if !Path::new(name)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err("inventory path must remain repository-relative".into());
            }
            Ok(name.to_owned())
        })
        .collect()
}

fn current_paths(list: &[u8], deleted: &[u8]) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut paths = git_paths(list)?;
    let deleted = git_paths(deleted)?;
    if !deleted.is_subset(&paths) {
        return Err("Git index changed during inventory".into());
    }
    paths.retain(|path| !deleted.contains(path));
    Ok((paths, deleted))
}

pub(crate) fn audit(root: &Path) -> Result<Value> {
    let list = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let deleted = git(root, &["ls-files", "--deleted", "-z"])?;
    let (paths, deleted) = current_paths(&list, &deleted)?;
    for path in &deleted {
        match fs::symlink_metadata(root.join(path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("deleted inventory entry changed during audit".into()),
        }
    }
    let mut python = Vec::new();
    let mut legacy = Vec::new();
    let mut unread = Vec::new();
    for path in &paths {
        let file = root.join(path);
        let relevant =
            path.ends_with(".py") || (path.starts_with("crates/") && path.ends_with(".rs"));
        if !relevant {
            continue;
        }
        let metadata = fs::symlink_metadata(&file)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > 8 * 1024 * 1024
        {
            unread.push(path.clone());
            continue;
        }
        let text = fs::read_to_string(&file)?;
        if path.ends_with(".py") {
            python.push(json!({"path":path,"bytes":metadata.len(),"lines":text.lines().count(),"disposition":disposition(path)}));
        }
        if path.starts_with("crates/")
            && ["ReCtm", "re_ctm", "re-ctm", "Re-CTM"]
                .iter()
                .any(|marker| text.contains(marker))
        {
            legacy.push(path.clone());
        }
    }
    let head = String::from_utf8(git(root, &["rev-parse", "HEAD"])?)?;
    Ok(json!({
        "schema_version":"1.0.0", "milestone":"MTM-016", "audit_completed":true,
        "base_head":head.trim(), "tracked_and_unignored_file_count":paths.len(),
        "pending_deleted_file_count":deleted.len(), "pending_deleted_files":deleted,
        "python_file_count":python.len(), "python_files":python,
        "legacy_rust_reference_file_count":legacy.len(), "legacy_rust_reference_files":legacy,
        "uninspected_source_files":unread,
        "rust_only_ready":python.is_empty() && legacy.is_empty() && unread.is_empty(),
        "interpretation":"Text references are retirement candidates, not proof of a runtime dependency. User Python tools are not forbidden."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_understands_unstaged_deletions_without_hiding_other_files() -> Result<()> {
        let (current, deleted) = current_paths(
            b"scripts/retired.py\0crates/a.rs\0crates/a.rs\0",
            b"scripts/retired.py\0",
        )?;
        assert_eq!(current, BTreeSet::from(["crates/a.rs".to_owned()]));
        assert_eq!(deleted, BTreeSet::from(["scripts/retired.py".to_owned()]));
        assert!(current_paths(b"crates/a.rs\0", b"unknown.rs\0").is_err());
        Ok(())
    }

    #[test]
    fn inventory_rejects_escaped_and_non_utf8_paths() {
        for bytes in [
            &b"../outside.rs\0"[..],
            &b"/outside.rs\0"[..],
            &b"bad\xff.rs\0"[..],
        ] {
            assert!(git_paths(bytes).is_err());
        }
    }

    #[test]
    fn every_python_category_has_an_explicit_retirement_owner() {
        assert!(disposition("conformance/python_shadow.py").contains("fixtures"));
        assert!(disposition("tests/test_security.py").contains("negative"));
        assert!(disposition("scripts/release_mtm.py").contains("rollback"));
        assert!(disposition("scripts/validate_records.py").contains("immutable"));
        assert!(disposition("scripts/other.py").contains("review"));
    }
}
